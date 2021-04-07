diff -aur Lib/ssl.py Lib/ssl.py
--- Lib/ssl.py	2020-10-05 15:07:58.000000000 +0000
+++ Lib/ssl.py	2021-03-02 04:23:32.026226000 +0000
@@ -111,6 +111,11 @@
     # LibreSSL does not provide RAND_egd
     pass
 
+try:
+    from _ssl import FIPS_mode, FIPS_mode_set
+except ImportError as e:
+    sys.stderr.write('error in importing\n')
+    sys.stderr.write(str(e))
 
 from _ssl import (
     HAS_SNI, HAS_ECDH, HAS_NPN, HAS_ALPN, HAS_SSLv2, HAS_SSLv3, HAS_TLSv1,
diff -aur Modules/Setup Modules/Setup
--- Modules/Setup	2020-10-05 15:07:58.000000000 +0000
+++ Modules/Setup	2021-03-02 04:24:28.071717000 +0000
@@ -207,14 +207,14 @@
 #_csv _csv.c
 
 # Socket module helper for socket(2)
-#_socket socketmodule.c
+_socket socketmodule.c
 
 # Socket module helper for SSL support; you must comment out the other
 # socket line above, and possibly edit the SSL variable:
-#SSL=/usr/local/ssl
-#_ssl _ssl.c \
-#	-DUSE_SSL -I$(SSL)/include -I$(SSL)/include/openssl \
-#	-L$(SSL)/lib -lssl -lcrypto
+SSL=/usr/local/ssl
+_ssl _ssl.c \
+	-DUSE_SSL -I$(SSL)/include -I$(SSL)/include/openssl \
+	-L$(SSL)/lib -lssl -lcrypto
 
 # The crypt module is now disabled by default because it breaks builds
 # on many systems (where -lcrypt is needed), e.g. Linux (I believe).
diff -aur Modules/_ssl.c Modules/_ssl.c
--- Modules/_ssl.c	2020-10-05 15:07:58.000000000 +0000
+++ Modules/_ssl.c	2021-03-02 04:25:30.930669000 +0000
@@ -5394,6 +5394,20 @@
     return PyLong_FromLong(RAND_status());
 }
 
+static PyObject *
+_ssl_FIPS_mode_impl(PyObject *module) {
+    return PyLong_FromLong(FIPS_mode());
+}
+
+static PyObject *
+_ssl_FIPS_mode_set_impl(PyObject *module, int n) {
+    if (FIPS_mode_set(n) == 0) {
+        _setSSLError(ERR_error_string(ERR_get_error(), NULL) , 0, __FILE__, __LINE__);
+        return NULL;
+    }
+    Py_RETURN_NONE;
+}
+
 #ifndef OPENSSL_NO_EGD
 /* LCOV_EXCL_START */
 /*[clinic input]
@@ -5875,6 +5889,8 @@
     _SSL_ENUM_CRLS_METHODDEF
     _SSL_TXT2OBJ_METHODDEF
     _SSL_NID2OBJ_METHODDEF
+    _SSL_FIPS_MODE_METHODDEF
+    _SSL_FIPS_MODE_SET_METHODDEF
     {NULL,                  NULL}            /* Sentinel */
 };
 
diff -aur Modules/clinic/_ssl.c.h Modules/clinic/_ssl.c.h
--- Modules/clinic/_ssl.c.h	2020-10-05 15:07:58.000000000 +0000
+++ Modules/clinic/_ssl.c.h	2021-03-02 04:27:06.120295000 +0000
@@ -1204,6 +1204,45 @@
     return _ssl_RAND_status_impl(module);
 }
 
+PyDoc_STRVAR(_ssl_FIPS_mode__doc__,
+"FIPS Mode");
+
+#define _SSL_FIPS_MODE_METHODDEF    \
+    {"FIPS_mode", (PyCFunction)_ssl_FIPS_mode, METH_NOARGS, _ssl_FIPS_mode__doc__},
+
+static PyObject *
+_ssl_FIPS_mode_impl(PyObject *module);
+
+static PyObject *
+_ssl_FIPS_mode(PyObject *module, PyObject *Py_UNUSED(ignored))
+{
+    return _ssl_FIPS_mode_impl(module);
+}
+
+PyDoc_STRVAR(_ssl_FIPS_mode_set_doc__,
+"FIPS Mode Set");
+
+#define _SSL_FIPS_MODE_SET_METHODDEF    \
+    {"FIPS_mode_set", (PyCFunction)_ssl_FIPS_mode_set, METH_O, _ssl_FIPS_mode_set_doc__},
+
+static PyObject *
+_ssl_FIPS_mode_set_impl(PyObject *module, int n);
+
+static PyObject *
+_ssl_FIPS_mode_set(PyObject *module, PyObject *arg)
+{
+    PyObject *return_value = NULL;
+    int n;
+
+    if (!PyArg_Parse(arg, "i:FIPS_mode_set", &n)) {
+        goto exit;
+    }
+    return_value = _ssl_FIPS_mode_set_impl(module, n);
+
+exit:
+    return return_value;
+}
+
 #if !defined(OPENSSL_NO_EGD)
 
 PyDoc_STRVAR(_ssl_RAND_egd__doc__,
