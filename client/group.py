class Group:
    """
    Represents a group chat with associated members and keys for each user.

    Attributes:
        _members (set): Set of members in the group chat.
        _member_keys (dict): Dictionary to store keys for each member in the group.

    Properties:
        members (set): Set of members in the group chat.
        member_keys (dict): Dictionary to store keys for each member in the group.

    """

    def __init__(self, members):
        """
        Initializes a Group object with the specified name and members.

        Args:
            name (str): The name of the group chat.
            members (list or set): List or set of members in the group chat.
        """
        self._members = members
        self._member_keys = {}

    @property
    def members(self):
        """
        set: Set of members in the group chat.
        """
        return self._members

    @property
    def member_keys(self):
        """
        dict: Dictionary to store keys for each member in the group.
        """
        return self._member_keys
        
    @property
    def name(self):
        """
        str: Comma-separated string of the group members' names.
        """
        return ",".join(self._members)
        
    @member_keys.setter
    def member_keys(self, keys):
        """
        Sets the member_keys attribute with the provided keys dictionary.

        Args:
            keys (dict): Dictionary containing keys for each member in the group.
        """
        self._member_keys = keys

    def set_member_key(self, member, key):
        """
        Sets the key for a specific member in the group.

        Args:
            member (str): The member in the group chat.
            key (str): The key used for message encryption and decryption for the member.
        """
        self._member_keys[member] = key

    def get_member_key(self, member):
        """
        Retrieves the key for a specific member in the group.

        Args:
            member (str): The username of the member.

        Returns:
            str: The key used for message encryption and decryption for the member, or None if the member is not found.
        """
        return self._member_keys.get(member)