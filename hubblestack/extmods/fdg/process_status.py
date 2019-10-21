"""
Flexible Data Gathering: process_status
=================================

This fdg module allows for displaying the currently-running
processes, with various options for filtering
"""


import logging


log = logging.getLogger(__name__)


def list_processes(chained=None, chained_status=None):
    """
    Return a list of processes containing the name of the currently running processes.

    ``chain`` and ``chain_status`` are ignored; they represent the value and status
        returned by the previous call.

    The first return value (status) will be True if the osquery query is successful
    and False otherwise. The second argument will be the the ouput (list of strings).
    """
    res = _run_query('SELECT name FROM processes')
    try:
        ret = _convert_to_str(res['data'])
    except (KeyError, TypeError):
        log.error('Invalid data type returned by osquery call %s.', res, exc_info=True)
        return False, None

    return bool(ret), ret


def _convert_to_str(process_data):
    """
    Convert list of dicts containing items as unicode or other data type to str.

    process_data
        input list of dicts to convert to str
    """
    if not process_data:
        return None
    ret = []
    try:
        for process in process_data:
            str_process = {str(name): str(val) for name, val in process.items()}
            ret.append(str_process)
    except (TypeError, AttributeError):
        log.error('Invalid argument type; must be list of dicts.', exc_info=True)
        return None

    return ret


def _run_query(query_sql):
    """
    Send the ``query_sql`` to osquery and return the results.

    query_sql
        The query to be executed
    """
    res = __salt__['nebula.query'](query_sql)
    try:
        if not res['result']:
            log.error("Error executing the osquery query: %s", res['error'])
            return None
    except (KeyError, TypeError):
        log.error('Invalid data type returned by osquery call %s.', res, exc_info=True)
        return None

    return res


def find_process(filter_sql, fields=None, format_chained=True, chained=None, chained_status=None):
    """
    Return a list of processes matching the filter criteria.

    By default, the ``filter_sql`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your query to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    filter
        String containing the `sql` syntax filtering.
        e.g. 'pid > 123'
             "name == 'foo'"
             "state == 'S'"
             "parent == 1 and state != 'R'"

    field
        String specifying extra fields to be returned about the processes, separated by comma.
        All possible fields:
            path,cmdline,state,cwd,root,uid,gid,euid,egid,suid,sgid,on_disk,wired_size,
            resident_size,total_size,user_time,system_time,disk_bytes_read,disk_bytes_written,
            start_time,parent,pgroup,threads,nice
        If nothing is passed, it will return only the name and PID.
        Pass '*' to select all possible fields.

    format_chained
        Boolean determining wether to format the filter_sql with the chained value or not.

    chained
        The value chained from the previous call.

    chained_status
        Status returned by the chained method.

    ``note``
        If no processes matched the filter or an invalid field is passed,
        the function returns an empty list.
    """
    if format_chained:
        try:
            filter_sql = filter_sql.format(chained)
        except (AttributeError, TypeError):
            log.error("Invalid arguments.", exc_info=True)
    # default fields to `name` and `PID`
    if fields:
        fields += ',name,pid'
    else:
        fields = 'name,pid'
    query = "SELECT {0} FROM processes WHERE {1}".format(fields, filter_sql)
    res = _run_query(query)
    try:
        ret = _convert_to_str(res['data'])
    except (KeyError, TypeError):
        log.error('Invalid data type returned by osquery call %s.', res, exc_info=True)
        return False, None

    return bool(ret), ret


def is_running(filter_sql, format_chained=True, chained=None, chained_status=None):
    """
    Check if the process matching the filter is running or not.
    Returns `True` if it is running and `False` otherwise.

    The first return value (status) will be True if the query finds a process matching a search
    and False othewise or if an error occurs. The second argument will be True if the state of
    the matched process is Running and False otherwise.

    filter_sql
        String containing the `sql` syntax filtering.

    format_chained
        Boolean determining wether to format the filter_sql with the chained value or not.

    chained
        The value chained from the previous call.

    ``note``
        If more than one process matches the search, the function returns `False`
         and reports an error.
    """
    if format_chained:
        try:
            filter_sql = filter_sql.format(chained)
        except (AttributeError, TypeError):
            log.error('Invalid arguments.', exc_info=True)
    query = 'SELECT state FROM processes where {0}'.format(filter_sql)
    res = _run_query(query)
    if not res:
        return False, None
    # more than one process
    if len(res['data']) > 1:
        log.error('Search outputs %d results. Should output only 1', len(res['data']))
        return False, None
    # no processses matched the search
    if not res['data']:
        return False, False
    # the process is in the Running state
    if str(res['data'][0]['state']) == 'R':
        return True, True

    return True, False


def find_children(parent_filter, parent_field=None, returned_fields=None,
                  format_chained=False, chained=None, chained_status=None):
    """
    Returns a list of processes (dict with process data) that match the filter criteria.

    The first return value (status) will be True if the query is successful and False othewise.
    The second argument will be a list of dict containing data about the filtered processes.

    parent_filter
        The value to look for in the parent. By default it will compare against the name,
        if `parent_field` is passed in, it will compare (for equality) against it.

    parent_field
        The field to filter the parent by. By default it is `name`.

    returned_fields
        String specifying extra fields to be returned about the processes, separated by comma.
        By default it returns name and PID.
        Pass in '*' to have return all possible fields.

    All possible fields for `returned_fields` and `parent_field`:
        path,cmdline,state,cwd,root,uid,gid,euid,egid,suid,sgid,on_disk,wired_size,resident_size,
        total_size,user_time,system_time,disk_bytes_read,disk_bytes_written,start_time,
        parent,pgroup,threads,nice

    chained_status
        Status returned by the chained method.
    """
    if format_chained:
        try:
            parent_filter = parent_filter.format(chained)
        except (AttributeError, TypeError):
            log.error('Invalid arguments.', exc_info=True)
            return False, None
    # default returned_fields to `name` and `PID`
    if returned_fields:
        returned_fields += ',name,pid'
    else:
        returned_fields = 'name,pid'
    # default parent_field to `name`
    if not parent_field:
        parent_field = 'name'
    query = "SELECT {0} FROM processes WHERE parent == " \
            "(SELECT pid FROM processes WHERE {1} == '{2}')".format(
                returned_fields, parent_field, parent_filter)
    res = _run_query(query)
    try:
        ret = _convert_to_str(res['data'])
    except (KeyError, TypeError):
        log.error('Invalid data type returned by osquery call %s.', res, exc_info=True)
        return False, None

    return bool(ret), ret
