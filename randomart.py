from collections import Counter
import hashlib

"""
Implements a randomart visualizer based on the Drunken Bishop algorithm used by SHH
http://www.dirk-loss.de/sshvis/drunken_bishop.pdf

By Finian Blackett
"""

NW = (-1, -1)
NE = (1, -1)
SW = (-1, 1)
SE = (1, 1)

DEFAULT_ROOM_SIZE = (17, 9)


def hex_to_dirs(hex_string):
    # Parse a hex string (fingerprint) into a series of directions
    assert len(hex_string) % 2 == 0

    bin_bytes = []

    # Get binary representations of each byte
    for pair in [hex_string[i:i + 2] for i in range(0, len(hex_string), 2)]:
        decimal = int(pair, 16)
        bin_bytes.append(bin(decimal)[2:].zfill(8))

    pairs = []

    # Split each binary representation and properly reverse
    for byte in bin_bytes:
        byte_split = [byte[i:i + 2] for i in range(0, len(byte), 2)]
        byte_split.reverse()
        pairs.extend(byte_split)

    direction_map = {'00': NW,
                     '01': NE,
                     '10': SW,
                     '11': SE}
    # Map each bit pair to a direction
    directions = [direction_map[j] for j in pairs]

    return directions


def get_coin_sym(coins):
    # Get our symbol based on the number of a coins in a cell

    return {
        0: ' ',
        1: '.',
        2: 'o',
        3: '+',
        4: '=',
        5: '*',
        6: 'B',
        7: 'O',
        8: 'X',
        9: '@',
        10: '%',
        11: '&',
        12: '#',
        13: '/',
        14: '^',
        15: 'S',
        16: 'E', }.get(coins, '!')


class RandomArt:
    def __init__(self, hashalg='', room_size=DEFAULT_ROOM_SIZE, start=None):
        self.hashalg = hashalg
        self.room_size = room_size
        if start is not None:
            self.start = start
        else:
            self.start = tuple([i // 2 for i in room_size])

    def __call__(self, hex_string):
        room = self.get_room(hex_string)
        return self.display(room)

    def get_position(self, position, move):
        # Get the new position based on a position and a move

        x, y = position

        dir_x, dir_y = move

        # Maximum x and y
        max_x, max_y = tuple([x - 1 for x in self.room_size])

        new_x, new_y = x + dir_x, y + dir_y

        # Handle stopping the bishop at the walls
        new_x = min(new_x, max_x)
        new_y = min(new_y, max_y)

        new_x = max(new_x, 0)
        new_y = max(new_y, 0)

        return new_x, new_y

    def get_room(self, hex_string):
        # Return a room based on a
        room = Counter()
        current_position = self.start
        for direction in hex_to_dirs(hex_string):
            current_position = self.get_position(current_position, direction)
            room[current_position] += 1

        # Set start and end positions
        room[self.start] = 15
        room[current_position] = 16

        return room

    def display(self, room):
        # Displays a room using the coin symbols. Adds borders and a hash algorithm name

        # Get the top and bottom borders
        room_x, room_y = self.room_size
        if self.hashalg != '':
            bottom = '+' + ('[' + self.hashalg + ']').center(room_x, '-') + '+'
        else:
            bottom = '+' + '-' * room_x + '+'

        top = '+' + '-' * room_x + '+\n'

        string = ''

        # Enumerate through all our positions and get the symbol for the coins
        string += top
        for y in range(room_y):
            string += '|'
            for x in range(room_x):
                string += get_coin_sym(room[(x, y)])
            string += '|\n'
        string += bottom

        return string


if __name__ == '__main__':
    while True:
        # Just display the randomart of user input using SHA3-512 and a 31x15 grid
        string = input('')

        hex_digest = hashlib.sha3_512(string.encode('utf-8')).hexdigest()

        r = RandomArt('SHA3-512', (31, 15))

        print(r(hex_digest))
