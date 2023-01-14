class State:
    def __init__(self, key_pair, peer_public_key, root_key, sending_key, reset=True):
        self.key_pair = key_pair
        self.peer_public_key = peer_public_key
        self.root_key = root_key
        self.sending_key = sending_key
        self.reset = reset