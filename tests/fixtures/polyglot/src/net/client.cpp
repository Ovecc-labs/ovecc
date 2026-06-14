#include <string>
#include "net/socket.h"

namespace net {
int connect() {
    Socket s;
    return s.open();
}
}
