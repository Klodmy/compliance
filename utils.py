def main():
    pass


def ex_check(name, allowed):
    for ex in allowed:
        if name.endswith(f".{ex.lower()}"):
            return True
    return False

if __name__ == "__main__":
    main()
