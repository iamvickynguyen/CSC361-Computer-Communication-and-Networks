SAME_ORDER = b'\xa1\xb2\xc3\xd4'

class Global_Header:
    def __init__(self, data):
        self.same_order = data.startswith(SAME_ORDER)
