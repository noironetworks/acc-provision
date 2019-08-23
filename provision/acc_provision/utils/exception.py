class Error(Exception):

    def __init__(self, message=None, **kwargs):
        if message is None:
            message = "Unknown error occurred."
        self.message = message
        super(Error, self).__init__(self.message)


class OverlappingSubnet(Error):
    """ Raised when overlapping subnet is found """

class InvalidAccProvisionConfigFile(Error):
    """ Raised when invalid acc provision config file provided."""  

class AccProvisionConfigFileNotFound(Error):
    """ Raised when acc provison config file not found. """
 

