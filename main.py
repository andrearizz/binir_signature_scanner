import argparse
import interpreter
import lifter
import os


def init_parser():
    description = "Tool for verify VEX IR signature in binary files through a rule file"

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description)

    parser.add_argument(
        "binary_file",
        type=str,
        help="Binary file name"
    )

    parser.add_argument(
        "rules_file",
        type=str,
        help="Rules file name"
    )

    parser.add_argument(
        "-f", "--function",
        type=str,
        required=False,
        default="",
        help="Search patterns in the specified function"
    )

    parser.add_argument(
        "-s", "--start",
        type=str,
        default="",
        help="Search patterns from this memory address to the end. If the -e, --end flag is specified, the search is"
             "limited to the range [start-end]"
    )

    parser.add_argument(
        "-e", "--end",
        type=str,
        default="",
        help="If the -s, --start flag is specified the patterns search will limited to [start-end]"
    )

    return parser


def main():
    parser = init_parser()
    args = parser.parse_args()

    # Nomi del binario e del file delle regole
    binary = os.path.abspath(args.binary_file)
    rules = os.path.abspath(args.rules_file)

    # Oggetto lifter e filename contenente la trasposizione in IR del binario
    if args.function:
        lift = lifter.Lifter(binary, function=args.function)
    elif args.start and args.end:
        lift = lifter.Lifter(binary, start_addr=int(args.start, 0), end_addr=int(args.end, 0))
    elif args.start and not args.end:
        lift = lifter.Lifter(binary, start_addr=int(args.start, 0))
    else:
        lift = lifter.Lifter(binary)
    vex = lift.lift()

    # Oggetto Interpreter che interpreterà le regole e verificherà che le condizioni siano soddisfatte
    interpret = interpreter.Interpreter(rules, vex)
    interpret.interprets()


if __name__ == '__main__':
    main()
