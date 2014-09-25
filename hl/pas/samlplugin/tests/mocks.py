from UserDict import UserDict

class SessionMock(UserDict):

    id = 'dummy'

    def set(self, k, v):
        self[k] = v

    def __getitem__(self, k, default=None):
        if self.has_key(k):
            return UserDict.__getitem__(self, k)
        return default

    delete = UserDict.__delitem__

class ResponseMock(object):

    shared_state = {}
    text = ''
    encoding = 'utf-8'

    def __init__(self, status, request, method=None, **kwargs):
        self.__dict__ = self.shared_state
        self.code = self.status_code = status
        self.request = request 
        self.method = method
        self.kwargs = kwargs

class UserMock(object):

    def __init__(self, id):
        self.id = id

    def getId(self):
        return self.id
