import lterrorcorrection
import argparse
import sys
import qrcode
import time
import os
import re
import io
import base64
from math import ceil

def main():
    parser = argparse.ArgumentParser(description='Split a file into multiple streamed QR codes using  '
                                                 'fountain coding scheme')

    parser.add_argument('-b', '--block-size', type=int, default=512)
    parser.add_argument('-d', '--duration', type=int, default=300,
                        help='The duration of each individual frame in the QR gif')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'),
                        default=sys.stdin.buffer, help='The filename or path of file to stream.')

    args = parser.parse_args()

    input_data = args.infile.read()

    data, score = lterrorcorrection.optimal_encoding(io.BytesIO(input_data), args.block_size, extra=5)

    current_path = os.getcwd()

    timestamp = str(round(time.time()))

    os.mkdir(os.path.join(current_path, timestamp))

    images = []

    for i, block in enumerate(data):
        print('Generating QR code #%s' % (i + 1))
        qr = qrcode.QRCode(version=None,
                           box_size=15,
                           border=10)
        qr.add_data(base64.b64encode(block))
        qr.make(fit=True)

        img = qr.make_image(fill_color='black', back_color='white')
        images.append(img)
        img.save(os.path.join(current_path, timestamp, '%s_%s.png' % (i, timestamp)))

    with open(os.path.join(current_path, timestamp, re.sub(r'\W+', '', args.infile.name)), 'wb') as f:
        f.write(input_data)
    args.infile.close()

    images = [j.convert('RGBA') for j in images]

    images[0].save(os.path.join(current_path, timestamp, re.sub(r'\W+', '', args.infile.name) + '.gif'), format='GIF', save_all=True, append_images=images[1:], duration=args.duration, loop=0)
    print('\nResults:\n-------------------------------')
    print('Generated %s images.' % len(images))
    print('Reccomended minimum number of images to print/display/use: %0.0f' % ceil(score * 1.2))

if __name__ == '__main__':
    main()
