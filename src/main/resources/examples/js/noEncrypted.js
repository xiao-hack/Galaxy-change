var Request = Java.type("org.m2sec.core.models.Request")
var Response = Java.type("org.m2sec.core.models.Response")

/**
 * 跨语言能力来自于graaljs
 * 按 Ctrl（command） + ` 可查看内置函数
 */

/**
 * HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。
 * @param {Request} request 请求对象
 * @returns 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_request_to_burp(request) {
    return request;
}


/**
 * HTTP请求从Burp将要发送到Server时被调用。在此处完成请求加密的代码就可以将加密后的请求报文发送到Server。
 * @param {Request} request 请求对象
 * @returns 经过处理后的request对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_request_to_server(request) {
    return request;
}


/**
 * HTTP响应从Server到达Burp时被调用。在此处完成响应解密的代码就可以在Burp中看到明文的响应报文。
 * @param {Response} response 响应对象
 * @returns 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_response_to_burp(response) {
    return response;
}


/**
 * HTTP响应从Burp将要发送到Client时被调用。在此处完成响应加密的代码就可以将加密后的响应报文返回给Client。
 * @param {Response} response 响应对象
 * @returns 经过处理后的response对象，返回null代表从当前节点开始流量不再需要处理
 */
function hook_response_to_client(response) {
    return response;
}



/**
 * 程序在最开始会自动调用该函数，在上方函数可以放心使用log对象
 */
function set_log(log1) {
    log = log1
}