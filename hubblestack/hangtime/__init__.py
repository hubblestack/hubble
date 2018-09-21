try:
    import signal

    # windows (et al?) has no concept of signal.SIGALRM force the issue here
    # and, if applicable, load a fake timer wrapper

    assert signal.SIGALRM > 0
    from linux_itimers import HangTime, hangtime_wrapper

except:
    from fake import HangTime, hangtime_wrapper
