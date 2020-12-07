# -*- coding: utf-8 -*-
'''
    hubblestack.serializers
    ~~~~~~~~~~~~~~~~~~~~~~

    This module implements all the serializers needed by hubblestack.
    Each serializer offers the same functions and attributes:

    :deserialize: function for deserializing string or stream

    :serialize: function for serializing a Python object

    :available: flag that tells if the serializer is available
                (all dependencies are met etc.)

'''

from hubblestack.exceptions import HubbleException, HubbleRenderError


class DeserializationError(HubbleRenderError, RuntimeError):
    """Raised when stream of string failed to be deserialized"""
    pass


class SerializationError(HubbleException, RuntimeError):
    """Raised when stream of string failed to be serialized"""
    pass
