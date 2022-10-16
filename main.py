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

    return parser


def main():
    parser = init_parser()
    args = parser.parse_args()

    # Nomi del binario e del file delle regole
    binary = os.path.abspath(args.binary_file)
    rules = os.path.abspath(args.rules_file)

    # Oggetto lifter e filename contenente la trasposizione in IR del binario
    lift = lifter.Lifter(binary)
    vex = lift.lift()

    # Oggetto Interpreter che interpreterà le regole e verificherà che le condizioni siano soddisfatte
    interpret = interpreter.Interpreter(rules, vex)
    interpret.interprets()


if __name__ == '__main__':
    main()
