"""
This module provides a Packet class for representing communication packets.

The Packet class allows creating Packet objects from JSON data, accessing packet attributes,
and converting Packet objects to JSON format.

Module Dependencies:
    - json: Provides methods for working with JSON data.

Classes:
    Packet: Represents a packet containing data for communication.
"""

import json


class Packet:
    """
    Represents a packet containing data for communication.

    This class provides methods to create Packet objects from JSON data, access packet attributes,
    and convert Packet objects to JSON format.

    Attributes:
        data (dict): Additional data for the packet.

    Methods:
        packet_type (property): Get the type of the packet.
        username (property): Get the username from the packet data.
        from_json(cls, json_data): Create a Packet object from JSON data.
        __getattr__(self, attr): Get the value of an attribute from the packet data.
        to_json(self): Convert the Packet object to JSON format.
    """

    def __init__(self, packet_type, **kwargs):
        self._packet_type = packet_type
        self.data = kwargs

    @property
    def packet_type(self):
        """
        Get the type of the packet.

        Returns:
            str: The type of the packet.
        """
        return self._packet_type

    @property
    def username(self):
        """
        Get the username from the packet data.

        Returns:
            str: The username.
        """
        return self.data.get('username')

    @classmethod
    def from_json(cls, json_data):
        """
        Create a Packet object from JSON data.

        Args:
            json_data (str): The JSON data representing the packet.

        Returns:
            Packet: The Packet object.
        """
        data = json.loads(json_data)
        packet_type = data['type']
        kwargs = data.copy()
        del kwargs['type']
        return cls(packet_type, **kwargs)

    def __getattr__(self, attr):
        """
        Get the value of an attribute from the packet data.

        Args:
            attr (str): The attribute name.

        Returns:
            Any: The value of the attribute.
        """
        return self.data.get(attr)

    def to_json(self):
        """
        Convert the Packet object to JSON format.

        Returns:
            str: The JSON representation of the Packet object.
        """
        data = {
            'type': self.packet_type,
            **self.data
        }
        return json.dumps(data)
