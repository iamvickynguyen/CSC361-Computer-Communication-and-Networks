import sys

def main():
    with open(sys.argv[1], 'rb') as f:
        print(f.read(5000))

if __name__ == "__main__":
    main()