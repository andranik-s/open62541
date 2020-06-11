#ifndef UA_EV_H_
#define UA_EV_H_

#include <open62541/config.h>
#include <open62541/types.h>

_UA_BEGIN_DECLS

struct UA_Ev_Loop;
typedef struct UA_Ev_Loop UA_Ev_Loop;

UA_UInt16 UA_EXPORT
UA_Ev_Loop_run_iterate(UA_Ev_Loop *loop, UA_Boolean waitInternal);

UA_StatusCode UA_EXPORT
UA_Ev_Loop_set_maxWaitTime(UA_Ev_Loop *loop, UA_Double maxWaitTime);

/* Callback where the application is either a client, a server, or an event loop */
typedef void (*UA_ApplicationCallback)(void *application, void *data);

typedef void (*UA_Ev_Callback)(UA_Ev_Loop *loop, void *data);

/*************** Timer Events ***************/

UA_StatusCode UA_EXPORT
__UA_Ev_addTimedCallback(UA_Ev_Loop *loop,
                         UA_ApplicationCallback callback, void *application, void *data,
                         UA_DateTime firstTime, UA_UInt64 interval, UA_Boolean repeated,
                         UA_UInt64 *timerId);

static UA_INLINE UA_StatusCode
UA_Ev_addRepeatedCallback(UA_Ev_Loop *loop, UA_Ev_Callback callback, void *data,
                          UA_Double interval_ms, UA_UInt64 *timerId) {
    return __UA_Ev_addTimedCallback(loop, (UA_ApplicationCallback)callback, loop, data,
                        UA_DateTime_nowMonotonic() + (UA_DateTime)interval, interval_ms,
                        true, timerId);
}

static UA_INLINE UA_StatusCode
UA_Ev_addTimedCallback(UA_Ev_Loop *loop, UA_Ev_Callback callback,
                       void *data, UA_DateTime date, UA_UInt64 *timerId) {
    return __UA_Ev_addTimedCallback(loop, (UA_ApplicationCallback)callback, loop, data,
                                    date, 0, false, timerId);
}

UA_StatusCode UA_EXPORT
UA_Ev_removeTimer(UA_Ev_Loop *loop, UA_UInt64 *timerId);

UA_StatusCode UA_EXPORT
UA_Ev_changeTimerInterval(UA_Ev_Loop *loop, UA_Double interval);

/*************** IO Events ***************/

#define UA_EV_POLLIN    0x001
#define UA_EV_POLLOUT	0x004
#define UA_EV_POLLERR   0x008

typedef (*UA_Ev_IOApplicationCallback)(void *application, void *data,
                                       UA_SOCKET socket, UA_UInt16 revents, UA_UInt16 *events);

typedef (*UA_Ev_IOCallback)(UA_Ev_Loop *loop, void *data,
                            UA_SOCKET socket, UA_UInt16 revents, UA_UInt16 *events);

UA_StatusCode UA_EXPORT
__UA_Ev_addIO(UA_Ev_Loop *loop,
              UA_Ev_IOApplicationCallback callback, void *application, void *data,
              UA_SOCKET socket, UA_UInt16 events, UA_UInt64 *ioId);

static UA_INLINE UA_StatusCode
UA_Ev_addIO(UA_Ev_Loop *loop, UA_Ev_IOCallback callback, void *data,
            UA_SOCKET socket, UA_UInt16 events, UA_UInt64 *ioId) {
    return __UA_Ev_addIO(loop, (UA_Ev_IOApplicationCallback)callback, loop, data,
                         socket, events, ioId);
}

UA_StatusCode UA_EXPORT
UA_Ev_IO_removeIO(UA_Ev_Loop *loop, UA_UInt64 ioId);

/*************** Cycled ***************/

/* Used for callbacks that need to be executed every cycle */

UA_StatusCode UA_EXPORT
__UA_Ev_addCycled(UA_Ev_Loop *loop,
                  UA_ApplicationCallback callback, void *application, void *data,
                  UA_UInt64 *cycledId);

static UA_INLINE UA_StatusCode
UA_Ev_addCycled(UA_Ev_Loop *loop,
                UA_Ev_Callback callback, void *data,
                UA_UInt64 *cycledId) {
    return __UA_Ev_addCycled(loop, (UA_ApplicationCallback)callback, loop, data, cycledId);
}

UA_StatusCode UA_EXPORT
UA_Ev_removeCycled(UA_Ev_Loop *loop, UA_UInt64 *cycledId);

_UA_END_DECLS

#endif /* UA_EV_H_ */

