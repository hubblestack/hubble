# These osquery daemon flags cannot be overridden by remote flagfile stored in file-servers.
OSQD_BLACKLISTED_FLAGS = ['config_plugin',
                          # options like filesystem,tls can be provided. As of Hubble 3.0, we always use 'filesystem'
                          'tls_hostname',
                          'tls_session_reuse',
                          'tls_client_cert',
                          'tls_client_key',
                          'tls_server_certs',
                          'disable_enrollment',
                          'enroll_secret_path',
                          'config_tls_endpoint',
                          'logger_tls_endpoint',
                          'enrollment_tls_endpoint',
                          'distributed_tls_read_endpoint',
                          'distributed_tls_write_endpoint',
                          'logger_plugin',
                          'distributed_plugin',
                          # Disable extensions and extensions related flag
                          'disable_extensions',
                          'extensions_socket',
                          'extensions_autoload',
                          'extensions_require',
                          'extensions_default_index']
