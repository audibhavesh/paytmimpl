package com.example.paytmimpl.checksum.crypto

import java.io.PrintStream


class SecurityException : Exception {
    var errorCode: String? = null
    var errorMessage: String? = null
    private var exception: Exception? = null

    constructor(errorCode: String?, errorMessage: String?) : super(errorMessage) {
        this.errorCode = errorCode
        this.errorMessage = errorMessage
    }

    constructor(errorMessage: String?) : super(errorMessage) {}
    constructor(cause: Throwable?) : super(cause) {}
    constructor(errorMessage: String?, cause: Throwable?) : super(
        errorMessage,
        cause
    ) {
    }

    constructor(errorMessage: String?, exception: Exception?) {
        this.errorMessage = errorMessage
        this.exception = exception
    }

    override fun printStackTrace(stream: PrintStream) {
        if (exception != null) {
            exception!!.printStackTrace(stream)
        }
    }

    companion object {
        private const val serialVersionUID = -3956900350777254445L
    }
}
