import lief

def is_pe_broken(file_path):
    try:
        pe = lief.parse(file_path)
        if pe is None:
            return True  # Failed to parse
        # Optional: you can do extra sanity checks
        if not pe.has_signatures and len(pe.sections) == 0:
            return True
        return False
    except lief.bad_file as e:
        print(f"Bad file: {e}")
        return True
    except Exception as e:
        print(f"Error parsing PE: {e}")
        return True

file_path = "best.exe"
if is_pe_broken(file_path):
    print("PE file is broken or invalid.")
else:
    print("PE file is valid.")
