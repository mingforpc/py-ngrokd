
ERR_SUCCESS = 0
ERR_FAILED = 1
ERR_CLOSE_SOCKET = 2
ERR_UNKNOWN_REQUEST = 100
ERR_UNREGISTERED_CLIENT_ID = 101
ERR_UNSUPPORTED_PROTOCOL = 102
ERR_URL_EXISTED = 103
ERR_CLIENT_ID_NOT_EXIST = 104

MSG = {
    ERR_SUCCESS: "Success",
    ERR_FAILED: "Failed with internal error",
    ERR_CLOSE_SOCKET: "Error, should close socket",
    ERR_UNKNOWN_REQUEST: "Unknown request type",
    ERR_UNREGISTERED_CLIENT_ID: "This connection has no login",
    ERR_UNSUPPORTED_PROTOCOL: "Unsupported protocol",
    ERR_URL_EXISTED: "url existed",
    ERR_CLIENT_ID_NOT_EXIST: "client id not exist in server",
}


def get_err_msg(err):
    if err not in MSG:
        return None
    else:
        return MSG[err]