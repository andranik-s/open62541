#include "ua_server_internal.h"
#include "open62541_queue.h"

#define UA_ENABLE_CUSTOM_AUDIT_EVENTS

#define DEFAULT_SEVERITY 100

#define UA_TWOSTATE_ID UA_QUALIFIEDNAME(0, "Id")
#define UA_CONDVAR_SOURCETIMESTAMP UA_QUALIFIEDNAME(0, "SourceTimestamp")
#define UA_CONDITION_RETAIN UA_QUALIFIEDNAME(0, "Retain")
#define UA_CONDITION_ENABLEDSTATE UA_QUALIFIEDNAME(0, "EnabledState")
#define UA_CONDITION_COMMENT UA_QUALIFIEDNAME(0, "Comment")
#define UA_CONDITION_LASTSEVERITY UA_QUALIFIEDNAME(0, "LastSeverity")
#define UA_CONDITION_QUALITY UA_QUALIFIEDNAME(0, "Quality")
#define UA_CONDITION_SEVERITY UA_QUALIFIEDNAME(0, "Severity")
#define UA_CONDITION_ACKEDSTATE UA_QUALIFIEDNAME(0, "AckedState")
#define UA_CONDITION_CONFIRMEDSTATE UA_QUALIFIEDNAME(0, "ConfirmedState")
#define UA_CONDITION_EVENTTYPE UA_QUALIFIEDNAME(0, "EventType")
#define UA_ALARM_ACTIVESTATE UA_QUALIFIEDNAME(0, "ActiveState")

#define LOCALE ""
#define UA_ENABLED_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Enabled")
#define UA_DISABLED_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Disabled")
#define UA_ACKED_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Acknowledged")
#define UA_NACKED_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Unacknowledged")
#define UA_CONFIRMED_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Confirmed")
#define UA_NCONFIRMED_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Unconfirmed")
#define UA_ACTIVE_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Active")
#define UA_NACTIVE_TXT UA_LOCALIZEDTEXT(LOCALE, (char*)"Inactive")

struct EventsEntry {
    LIST_ENTRY(EventsEntry) listEntry;
    UA_ByteString eventId;
    UA_NodeId conditionId;
};

static void EventsEntry_clear(struct EventsEntry *ee) {
    UA_ByteString_clear(&ee->eventId);
    UA_NodeId_clear(&ee->conditionId);
}

static void EventsEntry_delete(struct EventsEntry *ee) {
    EventsEntry_clear(ee);
    free(ee);
}

struct Events {
    LIST_HEAD(, EventsEntry) list;
};

static void
deleteReferencesSubset(UA_Node *node, size_t referencesDeleteSize,
                               UA_NodeId* referencesDelete) {
    /* Nothing to do */
    if(node->referencesSize == 0 || node->references == NULL)
        return;

    for(size_t i = node->referencesSize; i > 0; --i) {
        UA_NodeReferenceKind *refs = &node->references[i-1];

        /* Shall we keep the references of this type? */
        UA_Boolean skip = true;
        for(size_t j = 0; j < referencesDeleteSize; j++) {
            if(UA_NodeId_equal(&refs->referenceTypeId, &referencesDelete[j])) {
                skip = false;
                break;
            }
        }
        if(skip)
            continue;

        /* Remove references */
        for(size_t j = 0; j < refs->refTargetsSize; j++)
            UA_ExpandedNodeId_clear(&refs->refTargets[j].targetId);
        UA_free(refs->refTargets);
        UA_NodeId_clear(&refs->referenceTypeId);
        node->referencesSize--;

        /* Move last references-kind entry to this position */
        if(i-1 == node->referencesSize) /* Don't memcpy over the same position */
            continue;
        node->references[i-1] = node->references[node->referencesSize];
    }

    if(node->referencesSize > 0) {
        /* Realloc to save memory */
        UA_NodeReferenceKind *refs = (UA_NodeReferenceKind*)
            UA_realloc(node->references, sizeof(UA_NodeReferenceKind) * node->referencesSize);
        if(refs) /* Do nothing if realloc fails */
            node->references = refs;
        return;
    }

    /* The array is empty. Remove. */
    UA_free(node->references);
    node->references = NULL;
}

static UA_StatusCode
deepCopyNode(UA_Server *server, const UA_NodeId source, UA_NodeId *dest) {
    UA_Node *nodeCopy;
    UA_StatusCode retval = UA_NODESTORE_GETCOPY(server, &source, &nodeCopy);
    UA_NodeId_deleteMembers(&nodeCopy->nodeId);
    
    UA_NodeId *delRef = (UA_NodeId *)UA_Array_new(2, &UA_TYPES[UA_TYPES_NODEID]);
    delRef[0] = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    delRef[1] = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    deleteReferencesSubset(nodeCopy, 2, delRef);
    UA_Array_delete(delRef, 2, &UA_TYPES[UA_TYPES_NODEID]);

    nodeCopy->nodeId = UA_NODEID_NULL;
    retval = UA_NODESTORE_INSERT(server, nodeCopy, dest);
    retval = copyNodeChildren(server, &server->adminSession, &source, dest);
    UA_NodeId *sourceIdForCtx = UA_NodeId_new();
    UA_NodeId_copy(&source, sourceIdForCtx);
    UA_Server_setNodeContext(server, *dest, sourceIdForCtx);

/*
    UA_Server_addReference(server, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                           UA_EXPANDEDNODEID_NUMERIC(dest->namespaceIndex, dest->identifier.numeric), true);
    UA_Server_addReference(server, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                           UA_EXPANDEDNODEID_NUMERIC(dest->namespaceIndex, dest->identifier.numeric), true);*/

    return retval;
}

#define DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(ctype, uatype)                             \
    static UA_StatusCode write_##ctype(UA_Server *server, UA_NodeId obj,                 \
                                       const UA_QualifiedName prop, ctype cv) {          \
        UA_Variant v;                                                                    \
        UA_Variant_setScalarCopy(&v, &cv, &UA_TYPES[uatype]);                            \
        return writeObjectProperty(server, obj, prop, v);                                \
    }

DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(UA_Boolean, UA_TYPES_BOOLEAN)
DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(UA_DateTime, UA_TYPES_DATETIME)
DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(UA_UInt16, UA_TYPES_UINT16)
DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(UA_LocalizedText, UA_TYPES_LOCALIZEDTEXT)
DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(UA_NodeId, UA_TYPES_NODEID)
DEFINE_WRITE_SCALAR_PROPERTY_FUNCTION(UA_String, UA_TYPES_STRING)

#define DEFINE_READ_SCALAR_PROPERTY_FUNCTION(ctype, uatype)                              \
    static UA_StatusCode read_##ctype(UA_Server *server, UA_NodeId obj,                  \
                                      const UA_QualifiedName prop, ctype **cv) {         \
        UA_Variant v;                                                                    \
        UA_StatusCode retval = readObjectProperty(server, obj, prop, &v);                \
        v.storageType = UA_VARIANT_DATA_NODELETE;                                        \
        *cv = (ctype *)v.data;                                                           \
        UA_Variant_clear(&v);                                                            \
        return retval;                                                                   \
    }

DEFINE_READ_SCALAR_PROPERTY_FUNCTION(UA_NodeId, UA_TYPES_NODEID)

static UA_StatusCode
getNodeType_(UA_Server *server, const UA_NodeId nodeId, UA_NodeId *nodeTypeId) {
    UA_StatusCode statusCode = UA_STATUSCODE_GOOD;

    UA_BrowseDescription bd;
    UA_BrowseDescription_init(&bd);
    bd.nodeId = nodeId;
    bd.referenceTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASTYPEDEFINITION);
    bd.includeSubtypes = UA_TRUE;
    bd.browseDirection = UA_BROWSEDIRECTION_FORWARD;

    UA_BrowseResult br;
    UA_BrowseResult_init(&br);
    UA_UInt32 maxrefs = 0;
    Operation_Browse(server, &server->adminSession, &maxrefs, &bd, &br);
    if(br.statusCode != UA_STATUSCODE_GOOD) {
        *nodeTypeId = UA_NODEID_NULL;
        statusCode = br.statusCode;
        goto cleanup;
    }
    if(br.referencesSize == 0) {
        *nodeTypeId = UA_NODEID_NULL;
        statusCode = UA_STATUSCODE_BADINVALIDARGUMENT;
        goto cleanup;
    }

    UA_ReferenceDescription *rd = &br.references[0];
    UA_NodeId_copy(&rd->nodeId.nodeId, nodeTypeId);

cleanup:
    UA_BrowseResult_deleteMembers(&br);

    return statusCode;
}

static UA_Boolean
isConditionType(UA_Server *server, const UA_NodeId obj) {
    UA_NodeId hasSubtypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE);
    UA_NodeId conditionTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE);
    
    return isNodeInTree(server, &obj, &conditionTypeId, &hasSubtypeId, 1);
}

static UA_Boolean
isAcknowlageableConditionType(UA_Server *server, const UA_NodeId objTypeId) {
    UA_NodeId hasSubtypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE);
    UA_NodeId acknowledgeableConditionTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE);

    return isNodeInTree(server, &objTypeId, &acknowledgeableConditionTypeId, &hasSubtypeId, 1);
}

static UA_Boolean
isAlarmConditionType(UA_Server *server, const UA_NodeId objTypeId) {
    UA_NodeId hasSubtypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE);
    UA_NodeId alarmConditionTypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ALARMCONDITIONTYPE);

    return isNodeInTree(server, &objTypeId, &alarmConditionTypeId, &hasSubtypeId, 1);
}

UA_StatusCode
UA_getConditionId(UA_Server *server, const UA_NodeId *conditionNodeId, UA_NodeId *outConditionId) {
    UA_NodeId typeId;
    UA_StatusCode retval = getNodeType_(server, *conditionNodeId, &typeId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(!isConditionType(server, typeId))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!isAcknowlageableConditionType(server, typeId)) {
        UA_NodeId_copy(conditionNodeId, outConditionId);
        return UA_STATUSCODE_GOOD;
    }

    struct EventsEntry *ee = NULL;
    struct Events* events = ((struct Events*)server->aacCtx);
    LIST_FOREACH(ee, &events->list, listEntry) {
        if(UA_NodeId_equal(&ee->conditionId, conditionNodeId)){
            UA_NodeId *source;
            UA_Server_getNodeContext(server, ee->conditionId, (void**)&source);
            UA_NodeId_copy(source, outConditionId);

            return UA_STATUSCODE_GOOD;
        }
    }
    
    return UA_STATUSCODE_BADINVALIDARGUMENT;
}

static UA_StatusCode
setConditionVariable(UA_Server *server, const UA_NodeId condition, const UA_QualifiedName variable, const UA_Variant value) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId varNodeId = UA_NODEID_NULL;

    {
        UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, condition, 1, &variable);
        if(bpr.statusCode != UA_STATUSCODE_GOOD)
            return bpr.statusCode;

        varNodeId = bpr.targets[0].targetId.nodeId;
        UA_BrowsePathResult_deleteMembers(&bpr);
    }

    retval |= UA_Server_writeValue(server, varNodeId, value);
    retval |= write_UA_DateTime(server, varNodeId, UA_CONDVAR_SOURCETIMESTAMP, UA_DateTime_now());

    return retval;
}

static UA_StatusCode
setTwoStateVariable(UA_Server *server, const UA_NodeId condition, 
                    const UA_QualifiedName variable, const UA_LocalizedText text, bool id) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId varNodeId = UA_NODEID_NULL;

    {
        UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, condition, 1, &variable);
        if(bpr.statusCode != UA_STATUSCODE_GOOD)
            return bpr.statusCode;

        varNodeId = bpr.targets[0].targetId.nodeId;
        UA_BrowsePathResult_deleteMembers(&bpr);
    }

    UA_Variant vtext_;
    UA_Variant_setScalarCopy(&vtext_, &text, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);

    retval |= UA_Server_writeValue(server, varNodeId, vtext_);
    retval |= write_UA_Boolean(server, varNodeId, UA_TWOSTATE_ID, id);

    return retval;
}

static UA_StatusCode
getTwoStateVariableId(UA_Server *server, const UA_NodeId condition, 
                    const UA_QualifiedName variable, bool *id) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId varNodeId = UA_NODEID_NULL;

    {
        UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, condition, 1, &variable);
        if(bpr.statusCode != UA_STATUSCODE_GOOD)
            return bpr.statusCode;

        varNodeId = bpr.targets[0].targetId.nodeId;
        UA_BrowsePathResult_deleteMembers(&bpr);
    }

    UA_Variant v;
    retval = UA_Server_readObjectProperty(server, varNodeId, UA_TWOSTATE_ID, &v);
    if(retval == UA_STATUSCODE_GOOD)
        *id = *(UA_Boolean*)v.data;

    return retval;
}

static UA_StatusCode
setEnabledState(UA_Server *server, const UA_NodeId condition, UA_Boolean isEnabled) {
    UA_LocalizedText text = isEnabled ? UA_ENABLED_TXT : UA_DISABLED_TXT;
    return setTwoStateVariable(server, condition, UA_CONDITION_ENABLEDSTATE, text, isEnabled);
}

static UA_StatusCode
getEnabledState(UA_Server *server, const UA_NodeId condition, UA_Boolean *isEnabled) {
    return getTwoStateVariableId(server, condition, UA_CONDITION_ENABLEDSTATE, isEnabled);
}

static UA_StatusCode
setAckedState(UA_Server *server, const UA_NodeId condition, UA_Boolean isEnabled) {
    UA_LocalizedText text = isEnabled ? UA_ACKED_TXT : UA_NACKED_TXT;
    return setTwoStateVariable(server, condition, UA_CONDITION_ACKEDSTATE, text, isEnabled);
}

static UA_StatusCode
getAckedState(UA_Server *server, const UA_NodeId condition, UA_Boolean *isEnabled) {
    return getTwoStateVariableId(server, condition, UA_CONDITION_ACKEDSTATE, isEnabled);
}

static UA_StatusCode
setActiveState(UA_Server *server, const UA_NodeId condition, UA_Boolean isEnabled) {
    UA_LocalizedText text = isEnabled ? UA_ACTIVE_TXT : UA_NACTIVE_TXT;
    return setTwoStateVariable(server, condition, UA_ALARM_ACTIVESTATE, text, isEnabled);
}

// static UA_StatusCode
// getActiveState(UA_Server *server, const UA_NodeId condition, UA_Boolean *isEnabled) {
//     return getTwoStateVariableId(server, condition, UA_ALARM_ACTIVESTATE, isEnabled);
// }

/*static UA_StatusCode
setConfirmedState(UA_Server *server, const UA_NodeId condition, UA_Boolean isEnabled) {
    UA_LocalizedText text = isEnabled ? UA_CONFIRMED_TXT : UA_NCONFIRMED_TXT;
    return setTwoStateVariable(server, condition, UA_CONDITION_CONFIRMEDSTATE, text, isEnabled);
}*/

static UA_StatusCode
setComment(UA_Server *server, const UA_NodeId condition, UA_LocalizedText comment) {
    UA_Variant v;
    UA_Variant_setScalarCopy(&v, &comment, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    return setConditionVariable(server, condition, UA_CONDITION_COMMENT, v);
}

static UA_StatusCode
setLastSeveriry(UA_Server *server, const UA_NodeId condition, UA_UInt16 severity) {
    UA_Variant v;
    UA_Variant_setScalarCopy(&v, &severity, &UA_TYPES[UA_TYPES_UINT16]);
    return setConditionVariable(server, condition, UA_CONDITION_LASTSEVERITY, v);
}

static UA_StatusCode
setQuality(UA_Server *server, const UA_NodeId condition, UA_StatusCode statusCode) {
    UA_Variant v;
    UA_Variant_setScalarCopy(&v, &statusCode, &UA_TYPES[UA_TYPES_STATUSCODE]);
    return setConditionVariable(server, condition, UA_CONDITION_QUALITY, v);
}

static UA_StatusCode
setEventType(UA_Server *server, const UA_NodeId condition, const UA_NodeId eventType) {
    return write_UA_NodeId(server, condition, UA_CONDITION_EVENTTYPE, eventType);
}

static UA_StatusCode 
setRetain(UA_Server *server, const UA_NodeId condition, UA_Boolean retain) {
    return write_UA_Boolean(server, condition, UA_CONDITION_RETAIN, retain);
}

// static UA_StatusCode 
// setTime(UA_Server *server, const UA_NodeId condition, UA_DateTime time) {
//     return write_UA_DateTime(server, condition, UA_QUALIFIEDNAME(0, "Time"), time);
// }

static UA_StatusCode
setSeverity(UA_Server *server, const UA_NodeId condition, UA_UInt16 severity) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_Variant v;
    retval |= UA_Server_readObjectProperty(server, condition, UA_CONDITION_SEVERITY, &v);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(!UA_Variant_isEmpty(&v) && v.type->typeIndex == UA_TYPES_UINT16) {
        retval |= setLastSeveriry(server, condition, *(UA_UInt16*)v.data);
    }

    retval |= write_UA_UInt16(server, condition, UA_CONDITION_SEVERITY, severity);

    return retval;
}

static UA_StatusCode
setSourceNode(UA_Server *server, const UA_NodeId condition, const UA_NodeId sourceNode) {
    return write_UA_NodeId(server, condition, UA_QUALIFIEDNAME(0, "SourceNode"), sourceNode);
}

static UA_StatusCode
getSourceNode(UA_Server *server, const UA_NodeId condition, UA_NodeId **sourceNode) {
    return read_UA_NodeId(server, condition, UA_QUALIFIEDNAME(0, "SourceNode"), sourceNode);
}

/*static UA_StatusCode
setAckedState(UA_Server *server, const UA_NodeId condition, UA_Boolean bool) {
    return set
}*/

static UA_StatusCode
__initBaseEvent(UA_Server *server, const UA_NodeId event, UA_LocalizedText message) {
    return write_UA_LocalizedText(server, event, UA_QUALIFIEDNAME(0, "Message"), message);
}

static UA_StatusCode
__initAuditEvent(UA_Server *server, const UA_NodeId event, 
                 UA_LocalizedText message,
                 UA_Boolean status_, const UA_String clientAuditEntryId,
                 const UA_String clientUserId, const UA_String serverId) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    retval |= __initBaseEvent(server, event, message);
    retval |= write_UA_DateTime(server, event, UA_QUALIFIEDNAME(0, "ActionTimeStamp"), UA_DateTime_now());
    retval |= write_UA_String(server, event, UA_QUALIFIEDNAME(0, "ClientAuditEntryId"), clientAuditEntryId);
    retval |= write_UA_String(server, event, UA_QUALIFIEDNAME(0, "ClientUserId"), clientUserId);
    retval |= write_UA_String(server, event, UA_QUALIFIEDNAME(0, "ServerId"), serverId);
    retval |= write_UA_Boolean(server, event, UA_QUALIFIEDNAME(0, "Status"), status_);

    return retval;
}

static UA_StatusCode
__initAuditUpdateMethodEvent(UA_Server *server, const UA_NodeId event, 
                 UA_LocalizedText message,
                 UA_Boolean status_, const UA_String clientAuditEntryId,
                 const UA_String clientUserId, const UA_String serverId,
                 const UA_Variant *input, size_t inputSize,
                 UA_NodeId methodId) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    retval |= __initAuditEvent(server, event, message, status_, clientAuditEntryId, clientUserId, serverId);
    retval |= write_UA_NodeId(server, event, UA_QUALIFIEDNAME(0, "MethodId"), methodId);

    /* TODO: write input */

    return retval;
}

/*static UA_StatusCode
getChildId(UA_Server *server, const UA_NodeId obj, UA_QualifiedName subObjName, UA_NodeId *outId) {
    UA_BrowsePathResult bpr =
        UA_Server_browseSimplifiedBrowsePath(server, obj, 1, &subObjName);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;

    UA_NodeId_copy(&bpr.targets[0].targetId.nodeId, outId);
    UA_BrowsePathResult_deleteMembers(&bpr);

    return UA_STATUSCODE_GOOD;
}*/

static UA_StatusCode
__concatenateLocalizedTexsts(UA_LocalizedText *out, const size_t n, ...) {
    UA_LocalizedText_init(out);

    UA_Boolean differentLocales = UA_FALSE;

    va_list stringList;
    va_start(stringList, n);
    UA_LocalizedText lt0 = va_arg(stringList, UA_LocalizedText);
    UA_String locale = lt0.locale;
    UA_String_copy(&lt0.locale, &locale);
    size_t concatenatedSize = lt0.text.length;
    for(size_t i = 1; i < n; ++i) {
        UA_LocalizedText lt = va_arg(stringList, UA_LocalizedText);
        if(!UA_String_equal(&locale, &lt.locale))
            differentLocales = UA_TRUE;
        concatenatedSize += lt.text.length;
    }
    va_end(stringList);

    if(differentLocales)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_Byte *str = (UA_Byte*)UA_malloc(concatenatedSize*sizeof(UA_Byte));
    if(str == NULL)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    UA_String_copy(&locale, &out->locale);
    out->text.length = concatenatedSize;
    out->text.data = str;

    va_start(stringList, n);
    for(size_t i = 0; i < n; ++i) {
        UA_LocalizedText lt = va_arg(stringList, UA_LocalizedText);
        memcpy(str, lt.text.data, lt.text.length*sizeof(UA_Byte));
        str += lt.text.length;
    }
    va_end(stringList);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
triggerConditionEnableAuditEvent(UA_Server *server, const UA_NodeId condition, UA_Boolean enable, 
                            UA_Boolean status_, 
                            const UA_NodeId *sessionId, const UA_Variant *input, size_t inputSize) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId event;

    retval = UA_Server_createEvent(server, UA_NODEID_NUMERIC(0, UA_NS0ID_AUDITCONDITIONENABLEEVENTTYPE), &event);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_LocalizedText msg;
    UA_LocalizedText conditionDisplayName;
    UA_LocalizedText enableMsg = enable ? UA_LOCALIZEDTEXT("", " enable") : UA_LOCALIZEDTEXT("", " disable");
    if(UA_Server_readDisplayName(server, condition, &conditionDisplayName) != UA_STATUSCODE_GOOD)
        conditionDisplayName = UA_LOCALIZEDTEXT_ALLOC("", "<no_conditition_name>");

    __concatenateLocalizedTexsts(&msg, 2, conditionDisplayName, enableMsg);

    UA_String unknown = UA_STRING("unknown");//TODO
    retval = __initAuditUpdateMethodEvent(server, event, msg, status_, 
        unknown, unknown,
        unknown, input, inputSize, UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_ENABLE));

    retval = UA_Server_triggerEvent(server, event, condition, NULL, UA_TRUE);
    
    UA_LocalizedText_deleteMembers(&conditionDisplayName);
    UA_LocalizedText_deleteMembers(&msg);

    return retval;
}

/* We use a 16-Byte ByteString as an identifier */
// static UA_StatusCode
// generateEventId(UA_ByteString *generatedId) {
//     generatedId->data = (UA_Byte *) UA_malloc(16 * sizeof(UA_Byte));
//     if(!generatedId->data)
//         return UA_STATUSCODE_BADOUTOFMEMORY;
//     generatedId->length = 16;

//     UA_UInt32 *ids = (UA_UInt32*)generatedId->data;
//     ids[0] = UA_UInt32_random();
//     ids[1] = UA_UInt32_random();
//     ids[2] = UA_UInt32_random();
//     ids[3] = UA_UInt32_random();
//     return UA_STATUSCODE_GOOD;
// }

// static UA_StatusCode
// eventSetStandardFields(UA_Server *server, const UA_NodeId *event,
//                        const UA_NodeId *origin, UA_ByteString *outEventId) {
//     /* Set the SourceNode */
//     UA_StatusCode retval;
//     UA_QualifiedName name = UA_QUALIFIEDNAME(0, "SourceNode");
//     UA_BrowsePathResult bpr = browseSimplifiedBrowsePath(server, *event, 1, &name);
//     if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
//         retval = bpr.statusCode;
//         UA_BrowsePathResult_deleteMembers(&bpr);
//         return retval;
//     }
//     UA_Variant value;
//     UA_Variant_init(&value);
//     UA_Variant_setScalarCopy(&value, origin, &UA_TYPES[UA_TYPES_NODEID]);
//     retval = writeWithWriteValue(server, &bpr.targets[0].targetId.nodeId, UA_ATTRIBUTEID_VALUE, &UA_TYPES[UA_TYPES_VARIANT], &value);
//     UA_Variant_deleteMembers(&value);
//     UA_BrowsePathResult_deleteMembers(&bpr);
//     if(retval != UA_STATUSCODE_GOOD)
//         return retval;

//     /* Set the ReceiveTime */
//     name = UA_QUALIFIEDNAME(0, "ReceiveTime");
//     bpr = browseSimplifiedBrowsePath(server, *event, 1, &name);
//     if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
//         retval = bpr.statusCode;
//         UA_BrowsePathResult_deleteMembers(&bpr);
//         return retval;
//     }
//     UA_DateTime rcvTime = UA_DateTime_now();
//     UA_Variant_setScalar(&value, &rcvTime, &UA_TYPES[UA_TYPES_DATETIME]);
//     retval = writeWithWriteValue(server, &bpr.targets[0].targetId.nodeId, UA_ATTRIBUTEID_VALUE, &UA_TYPES[UA_TYPES_VARIANT], &value);
//     UA_BrowsePathResult_deleteMembers(&bpr);
//     if(retval != UA_STATUSCODE_GOOD)
//         return retval;

//     /* Set the EventId */
//     UA_ByteString eventId = UA_BYTESTRING_NULL;
//     retval = generateEventId(&eventId);
//     if(retval != UA_STATUSCODE_GOOD)
//         return retval;
//     name = UA_QUALIFIEDNAME(0, "EventId");
//     bpr = browseSimplifiedBrowsePath(server, *event, 1, &name);
//     if(bpr.statusCode != UA_STATUSCODE_GOOD || bpr.targetsSize < 1) {
//         retval = bpr.statusCode;
//         UA_ByteString_deleteMembers(&eventId);
//         UA_BrowsePathResult_deleteMembers(&bpr);
//         return retval;
//     }
//     UA_Variant_init(&value);
//     UA_Variant_setScalar(&value, &eventId, &UA_TYPES[UA_TYPES_BYTESTRING]);
//     retval = writeWithWriteValue(server, &bpr.targets[0].targetId.nodeId, UA_ATTRIBUTEID_VALUE, &UA_TYPES[UA_TYPES_VARIANT], &value);
//     UA_BrowsePathResult_deleteMembers(&bpr);
//     if(retval != UA_STATUSCODE_GOOD) {
//         UA_ByteString_deleteMembers(&eventId);
//         return retval;
//     }

//     /* Return the EventId */
//     if(outEventId)
//         *outEventId = eventId;
//     else
//         UA_ByteString_deleteMembers(&eventId);

//     return UA_STATUSCODE_GOOD;
// }

static UA_StatusCode
initEvent(UA_Server *server, const UA_NodeId eventId) {
    UA_StatusCode retval;
    retval = write_UA_DateTime(server, eventId, UA_QUALIFIEDNAME(0, "Time"), UA_DateTime_now());
    return retval;
}

static UA_StatusCode
createBranch(UA_Server *server, const UA_NodeId conditionId, UA_NodeId *branchId) {
    static unsigned int bn = 1;
    UA_StatusCode retval;
    retval = deepCopyNode(server, conditionId, branchId);
    retval |= write_UA_NodeId(server, *branchId, UA_QUALIFIEDNAME(0, "BranchId"), UA_NODEID_NUMERIC(11, bn++));
    retval |= setAckedState(server, *branchId, UA_FALSE);
    //retval |= setConfirmedState(server, condition, UA_FALSE);
    return retval;
}

static UA_StatusCode
triggerCondition(UA_Server *server, const UA_NodeId conditionId, const UA_NodeId originId) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    struct Events* events = ((struct Events*)server->aacCtx);
    struct EventsEntry *entry = (struct EventsEntry *)UA_malloc(sizeof(struct EventsEntry));

    UA_NodeId conditionType;
    getNodeType_(server, conditionId, &conditionType);
    if(isAcknowlageableConditionType(server, conditionType)) {
        createBranch(server, conditionId, &entry->conditionId);
    } else {
        UA_NodeId_copy(&conditionId, &entry->conditionId);
    }

    /*retval |= setTime(server, entry->conditionId, UA_DateTime_now());
    retval |= eventSetStandardFields(server, &entry->conditionId, &conditionId, &entry->eventId);

    LIST_INSERT_HEAD(&events->list, entry, listEntry);

    retval |= UA_Server_triggerEvent2(server, entry->conditionId, conditionId, &entry->eventId, UA_FALSE);*/

    initEvent(server, entry->conditionId);
    LIST_INSERT_HEAD(&events->list, entry, listEntry);
    retval |= UA_Server_triggerEvent(server, entry->conditionId, conditionId, &entry->eventId, UA_FALSE);

    return retval;
}

static UA_StatusCode
enableMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output) {
    if(isConditionType(server, *objectId))
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Boolean isEnabled;
    retval = getEnabledState(server, *objectId, &isEnabled);
    if(retval == UA_STATUSCODE_GOOD) {
        if(!isEnabled)
            retval = setEnabledState(server, *objectId, UA_TRUE);
        else
            retval = UA_STATUSCODE_BADCONDITIONALREADYENABLED;
    }
    
    triggerConditionEnableAuditEvent(server, *objectId, UA_TRUE, retval == UA_STATUSCODE_GOOD,
        sessionId, input, inputSize);

    triggerCondition(server, *objectId, *objectId);

    return retval;
}

static UA_StatusCode
disableMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output) {
    if(isConditionType(server, *objectId))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Boolean isEnabled;
    retval = getEnabledState(server, *objectId, &isEnabled);
    if(retval == UA_STATUSCODE_GOOD) {
        if(isEnabled)
            retval = setEnabledState(server, *objectId, UA_FALSE);
        else
            retval = UA_STATUSCODE_BADCONDITIONALREADYDISABLED;
    }
    
    triggerConditionEnableAuditEvent(server, *objectId, UA_FALSE, retval == UA_STATUSCODE_GOOD,
        sessionId, input, inputSize);

    triggerCondition(server, *objectId, *objectId);
        
    return retval;
}

static UA_StatusCode
setEnableMethod(UA_Server *server) {
    return UA_Server_setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_ENABLE), enableMethodCallback);
}

static UA_StatusCode
setDisableMethod(UA_Server *server) {
    return UA_Server_setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_DISABLE), disableMethodCallback);
}

static UA_StatusCode
addHasConditionRefence(UA_Server *server, const UA_NodeId condition, const UA_NodeId conditionSource) {
    return UA_Server_addReference(server, conditionSource, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCONDITION),
                                  UA_EXPANDEDNODEID_NUMERIC(condition.namespaceIndex, condition.identifier.numeric), UA_TRUE);
}

static UA_StatusCode
initCondtion(UA_Server *server, const UA_NodeId condition, const UA_NodeId conditionSource) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    
    UA_NodeId eventTypeId;
    getNodeType_(server, condition, &eventTypeId);

    retval |= addHasConditionRefence(server, condition, conditionSource);
    retval |= setEventType(server, condition, eventTypeId);
    retval |= setSourceNode(server, condition, conditionSource);
    retval |= setRetain(server, condition, UA_TRUE);
    retval |= setEnabledState(server, condition, UA_TRUE);
    retval |= setComment(server, condition, UA_LOCALIZEDTEXT(LOCALE, ""));
    retval |= setSeverity(server, condition, DEFAULT_SEVERITY);
    retval |= setQuality(server, condition, UA_STATUSCODE_GOOD);

    return retval;
}

static UA_StatusCode
getParent(UA_Server *server, const UA_NodeId *field, UA_NodeId *parent) {
    *parent = UA_NODEID_NULL;
    UA_NodeId hasPropertyType = UA_NODEID_NUMERIC(0, UA_NS0ID_HASPROPERTY);
    UA_NodeId hasComponentType = UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT);
    const UA_Node *fieldNode = UA_NODESTORE_GET(server, field);
    if(!fieldNode)
        return UA_STATUSCODE_BADNOTFOUND;
    UA_StatusCode retval = UA_STATUSCODE_BADNOTFOUND;
    for(size_t i = 0; i < fieldNode->referencesSize; i++) {
        UA_NodeReferenceKind *rk = &fieldNode->references[i];
        if((UA_NodeId_equal(&rk->referenceTypeId, &hasPropertyType) ||
            UA_NodeId_equal(&rk->referenceTypeId, &hasComponentType)) &&
           true == rk->isInverse) {
            retval = UA_NodeId_copy(&rk->refTargets->targetId.nodeId, parent);
            break;
        }
    }
    UA_NODESTORE_RELEASE(server, (const UA_Node *)fieldNode);
    return retval;
}

static void
setAlramActiveCallback(UA_Server *server, const UA_NodeId *sessionId,
                    void *sessionContext, const UA_NodeId *nodeId,
                    void *nodeContext, const UA_NumericRange *range,
                    const UA_DataValue *data) {
    UA_NodeId twoStateVariableId;
    UA_StatusCode retval = getParent(server, nodeId, &twoStateVariableId);
    if(retval)
        return;
    UA_NodeId alarmId;
    retval = getParent(server, &twoStateVariableId, &alarmId);
    if(retval)
        return;
    bool currentActive = *(UA_Boolean*)data->value.data;
    bool prevActive = !currentActive;
    UA_Variant activeTxt;
    retval = UA_Server_readValue(server, twoStateVariableId, &activeTxt);
    if(!retval) {
        if(activeTxt.type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]) {
            UA_LocalizedText *txt = (UA_LocalizedText*)activeTxt.data;
            UA_LocalizedText acTxt = UA_ACTIVE_TXT;
            prevActive = UA_String_equal(&txt->locale, &acTxt.locale) &&
                UA_String_equal(&txt->text, &acTxt.text);
        }
        UA_Variant_clear(&activeTxt);
    }
    UA_LocalizedText acTxt = currentActive ? UA_ACTIVE_TXT : UA_NACTIVE_TXT;
    UA_Variant_setScalar(&activeTxt, &acTxt, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
    UA_Server_writeValue(server, twoStateVariableId, activeTxt);
    if(currentActive != prevActive) {
        UA_NodeId *sourceNode;
        getSourceNode(server, alarmId, &sourceNode);
        triggerCondition(server, alarmId, *sourceNode);
        UA_NodeId_delete(sourceNode);
    }
    UA_NodeId_clear(&twoStateVariableId);
    UA_NodeId_clear(&alarmId);
}

static UA_StatusCode
initAlarmCondition(UA_Server *server, const UA_NodeId condition) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= setActiveState(server, condition, false);
    UA_STACKARRAY(UA_QualifiedName, idpath, 2) = { UA_QUALIFIEDNAME(0, "ActiveState"), UA_QUALIFIEDNAME(0, "Id") };
    UA_BrowsePathResult bpr = UA_Server_browseSimplifiedBrowsePath(server, condition, 2, idpath);
    if(bpr.statusCode != UA_STATUSCODE_GOOD)
        return bpr.statusCode;
    if(bpr.targetsSize != 1)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_NodeId activeStateId = bpr.targets[0].targetId.nodeId;
    UA_ValueCallback callback;
    callback.onRead = NULL;
    callback.onWrite = setAlramActiveCallback;
    UA_Server_setVariableNode_valueCallback(server, activeStateId, callback);
    UA_BrowsePathResult_deleteMembers(&bpr);
    return retval;
}

static UA_StatusCode
initAcknowlagebleCondtion(UA_Server *server, const UA_NodeId condition) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    /*UA_VariableAttributes attr = UA_VariableAttributes_default;
    attr.displayName.locale = UA_STRING("");
    attr.displayName.text = UA_CONDITION_CONFIRMEDSTATE.name;
    UA_NodeId_copy(&UA_TYPES[UA_TYPES_LOCALIZEDTEXT].typeId, &attr.dataType);
    attr.valueRank = -1;
    retval |= UA_Server_addVariableNode(server, UA_NODEID_NULL, condition, 
        UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_CONDITION_CONFIRMEDSTATE, 
        UA_NODEID_NUMERIC(0, UA_NS0ID_TWOSTATEVARIABLETYPE), attr, NULL, NULL);

    retval |= UA_Server_addReference(server, condition, UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT),
                                    UA_EXPANDEDNODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_CONFIRM), true);*/

    return retval;
}

static void
makeRefreshEventsConcrete(UA_Server *server) {
    UA_NodeId refreshStartEventTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHSTARTEVENTTYPE);
    UA_NodeId refreshEndEventTypeNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHENDEVENTTYPE);
    const UA_Node* refreshStartEventType = UA_NODESTORE_GET(server, &refreshStartEventTypeNodeId);
    const UA_Node* refreshEndEventType = UA_NODESTORE_GET(server, &refreshEndEventTypeNodeId);

    if(false == ((const UA_ObjectTypeNode*)refreshStartEventType)->isAbstract &&
       false == ((const UA_ObjectTypeNode*)refreshEndEventType)->isAbstract) {
        UA_NODESTORE_RELEASE(server, refreshStartEventType);
        UA_NODESTORE_RELEASE(server, refreshEndEventType);
    }
    else
    {
        UA_NODESTORE_RELEASE(server, refreshStartEventType);
        UA_NODESTORE_RELEASE(server, refreshEndEventType);
        UA_Node* refreshStartEventTypeInner;
        UA_Node* refreshEndEventTypeInner;
        if(UA_STATUSCODE_GOOD != UA_NODESTORE_GETCOPY(server, &refreshStartEventTypeNodeId, &refreshStartEventTypeInner) ||
           UA_STATUSCODE_GOOD != UA_NODESTORE_GETCOPY(server, &refreshEndEventTypeNodeId, &refreshEndEventTypeInner))
            UA_assert(0);
        else
        {
            ((UA_ObjectTypeNode*)refreshStartEventTypeInner)->isAbstract = false;
            ((UA_ObjectTypeNode*)refreshEndEventTypeInner)->isAbstract = false;
            UA_NODESTORE_REPLACE(server, refreshStartEventTypeInner);
            UA_NODESTORE_REPLACE(server, refreshEndEventTypeInner);
        }
    }
}

static UA_StatusCode
refresh(UA_Server *server, UA_MonitoredItem *monItem) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId serverNode = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER);
    UA_NodeId refreshStart;
    UA_NodeId refreshEnd;
    retval |= UA_Server_createEvent(server, UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHSTARTEVENTTYPE), &refreshStart);
    retval |= UA_Server_createEvent(server, UA_NODEID_NUMERIC(0, UA_NS0ID_REFRESHENDEVENTTYPE), &refreshEnd);

    //retval |= eventSetStandardFields(server, &refreshStart, &serverNode, NULL);
    //retval |= UA_Event_addEventToMonitoredItem(server, &refreshStart, monItem);
    retval |= UA_Server_triggerEvent(server, refreshStart, serverNode, NULL, true);

    struct EventsEntry *ee = NULL;
    struct Events* events = ((struct Events*)server->aacCtx);
    LIST_FOREACH(ee, &events->list, listEntry) {
        UA_Event_addEventToMonitoredItem(server, &ee->conditionId, monItem);
    }

    //retval |= eventSetStandardFields(server, &refreshEnd, &serverNode, NULL);
    //retval |= UA_Event_addEventToMonitoredItem(server, &refreshEnd, monItem);
    retval |= UA_Server_triggerEvent(server, refreshEnd, serverNode, NULL, true);

    deleteNode(server, refreshStart, UA_TRUE);
    deleteNode(server, refreshEnd, UA_TRUE);

    return retval;
}

static UA_StatusCode
refreshMethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_Session *session = UA_Server_getSessionById(server, sessionId);
    UA_Subscription *subscription = UA_Session_getSubscriptionById(session, *((UA_UInt32 *)input[0].data));
    if(subscription == NULL)
        return UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
    UA_MonitoredItem *monitoredItem;
    LIST_FOREACH(monitoredItem, &subscription->monitoredItems, listEntry) {
        retval |= refresh(server, monitoredItem);
    }
        
    return retval;
}

static UA_StatusCode
refresh2MethodCallback(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output) {
    UA_Session *session = UA_Server_getSessionById(server, sessionId);
    UA_Subscription *subscription = UA_Session_getSubscriptionById(session, *((UA_UInt32 *)input[0].data));
    if(subscription == NULL)
        return UA_STATUSCODE_BADSUBSCRIPTIONIDINVALID;
    UA_MonitoredItem *monitoredItem = UA_Subscription_getMonitoredItem(subscription, *((UA_UInt32 *)input[1].data));
    if(monitoredItem == NULL)
        return UA_STATUSCODE_BADMONITOREDITEMIDINVALID;

    return refresh(server, monitoredItem);
}

static UA_StatusCode
acknowledgeCallback(UA_Server *server, const UA_NodeId *sessionId,
                     void *sessionContext, const UA_NodeId *methodId,
                     void *methodContext, const UA_NodeId *objectId,
                     void *objectContext, size_t inputSize,
                     const UA_Variant *input, size_t outputSize,
                     UA_Variant *output) {
    UA_ByteString *eventId = (UA_ByteString*)input[0].data;
    UA_LocalizedText *comment = (UA_LocalizedText*)input[1].data;
    struct EventsEntry *ee = NULL, *ee_tmp = NULL;
    struct Events* events = ((struct Events*)server->aacCtx);
    LIST_FOREACH_SAFE(ee, &events->list, listEntry, ee_tmp) {
        if(UA_ByteString_equal(&ee->eventId, eventId)){
            UA_Boolean isAcked;
            UA_StatusCode retval = getAckedState(server, ee->conditionId, &isAcked);
            if(retval)
                return UA_STATUSCODE_BADMETHODINVALID;
            if(isAcked)
                return UA_STATUSCODE_BADCONDITIONBRANCHALREADYACKED;
            setComment(server, ee->conditionId, *comment);
            setAckedState(server, ee->conditionId, true);
            setRetain(server, ee->conditionId, false);
            UA_NodeId *source;
            UA_Server_getNodeContext(server, ee->conditionId, (void**)&source);
            retval |= UA_Server_triggerEvent(server, ee->conditionId, *source, NULL, UA_FALSE);
            UA_Server_deleteNode(server, ee->conditionId, false);
            LIST_REMOVE(ee, listEntry);
            EventsEntry_delete(ee);
            return UA_STATUSCODE_GOOD;
        }
    }
    return UA_STATUSCODE_BADNODEIDINVALID;
}

static UA_StatusCode
__UA_Server_setConditionRefreshMethods(UA_Server *server) {
    UA_StatusCode retval;
    retval  = UA_Server_setMethodNode_callback(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH), refreshMethodCallback);
    retval |= UA_Server_setMethodNode_callback(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_CONDITIONTYPE_CONDITIONREFRESH2), refresh2MethodCallback);
    retval |= UA_Server_setMethodNode_callback(server,
        UA_NODEID_NUMERIC(0, UA_NS0ID_ACKNOWLEDGEABLECONDITIONTYPE_ACKNOWLEDGE), acknowledgeCallback);
    retval |= setEnableMethod(server);
    retval |= setDisableMethod(server);
    return retval;
}

static UA_StatusCode
__UA_Server_enableAlarmsAndConditions(UA_Server *server) {
    struct Events *e = (struct Events*)UA_malloc(sizeof(struct Events));
    LIST_INIT(&e->list);
    server->aacCtx = e;
    
    makeRefreshEventsConcrete(server);
    return __UA_Server_setConditionRefreshMethods(server);
}

UA_StatusCode
UA_Server_initCondtion(UA_Server *server, const UA_NodeId condition, const UA_NodeId conditionSource) {
    UA_StatusCode statusCode = UA_STATUSCODE_GOOD;

    if(server->aacCtx == NULL){
        UA_StatusCode sc = __UA_Server_enableAlarmsAndConditions(server);
        if(sc != UA_STATUSCODE_GOOD)
            return sc;
    }

    UA_NodeId eventTypeId;
    getNodeType_(server, condition, &eventTypeId);
    if(isConditionType(server, eventTypeId)) {
        initCondtion(server, condition, conditionSource);

        if(isAcknowlageableConditionType(server, eventTypeId)) {
            initAcknowlagebleCondtion(server, condition);

            if(isAlarmConditionType(server, eventTypeId)) {
                initAlarmCondition(server, condition);
            }
        }
    } else {
        statusCode = UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    return statusCode;
}