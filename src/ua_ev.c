#include <open62541/ev.h>
#include "ua_timer.h"

#define UA_EV_WATCHER_COMMON                                \
    /* Id of the entry (read only) */                       \
    UA_UInt64 id;                                           \
    /* For compatability only (consider same as data) */    \    
    void *application;                                      \
     /* Associated data */                                  \
    void *data;                                             \
    /* Executed on wather stop if set */                    \
    UA_Ev_WatcherCleanupF cleanup

typedef struct {
    UA_EV_WATCHER_COMMON;
} UA_Ev_Watcher;

typedef struct {
    UA_EV_WATCHER_COMMON;
    UA_Double interval;             /* Interval in 100ns resolution 
                                     *   Interval change outside of the callback
                                     *   will take effect only after one loop iteration.
                                     *   Use UA_Ev_changeTimerInterval for the changes
                                     *   to take effect immediately. */
    UA_Boolean repeated;            /* Repeated callback? */

    UA_Ev_Callback callback;
} UA_Ev_Timer;

typedef struct {
    UA_EV_WATCHER_COMMON;
    UA_SOCKET socket;
    UA_UInt16 events;       /* Bitmap of events we're interested in */
} UA_Ev_IO;

typedef struct {
    UA_EV_WATCHER_COMMON;
    UA_Ev_Callback callback;
} UA_Ev_Cycled;

struct UA_Ev_Loop {
    UA_Timer timer;
    UA_Ev_IO *io;
    UA_UInt64 maxWaitTime;
};