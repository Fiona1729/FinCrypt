import lterrorcorrection
import argparse
import sys
import qrcode
import time
import os

def main():
    parser = argparse.ArgumentParser(description='Split a file into multiple streamed QR codes using a'
                                                 ' fountain coding scheme')

    parser.add_argument('-b', '--block-size', type=int, default=512)
    parser.add_argument('infile', nargs='?', type=argparse.FileType('rb'),
                        default=sys.stdin.buffer, help='The filename or path of file to stream.')

    args = parser.parse_args()

    data, score = lterrorcorrection.optimal_encoding(args.infile, args.block_size)

    current_path = os.getcwd()

    timestamp = str(round(time.time()))

    os.mkdir(os.path.join(current_path, timestamp))

    for i, block in enumerate(data):
        print('Generating QR code #%s' % i)
        qr = qrcode.QRCode(version=None,
                           box_size=15,
                           border=10)
        qr.add_data(block)
        qr.make(fit=True)

        img = qr.make_image(fill_color='black', back_color='white')
        img.save(os.path.join(current_path, timestamp, '%s_%s.png' % (i, timestamp)))

    with open(os.path.join(current_path, timestamp, args.infile.name), 'wb') as f:
        args.infile.seek(0)
        f.write(args.infile.read())
    args.infile.close()

if __name__ == '__main__':
    main()