import lief

def append_pe_data(pe_path: str, output_path: str, data: bytes, as_section: bool = False, section_name: str = ".extra"):
    """
    Append data to a PE file.
    
    :param pe_path: Path to the original PE file.
    :param output_path: Path to write the modified PE.
    :param data: Bytes to append.
    :param as_section: If True, add a new section. Otherwise, append to overlay.
    :param section_name: Name of the new section (if as_section=True).
    """
    pe = lief.parse(pe_path)
    
    if not pe:
        raise RuntimeError(f"Failed to parse PE: {pe_path}")

    if as_section:
        # Create a new section
        new_section = lief.PE.Section(section_name)
        new_section.content = list(data)
        # Set section characteristics (readable, initialized)
        new_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ |
            lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
        )
        # Add section to PE
        pe.add_section(new_section, lief.PE.SECTION_TYPES.DATA)
        print(f"[+] Added new section '{section_name}' with {len(data)} bytes")
    else:
        # Append to overlay
        pe.overlay += data
        print(f"[+] Appended {len(data)} bytes to overlay")

    # Write modified PE
    pe.write(output_path)
    print(f"[+] Written modified PE to '{output_path}'")

# Example usage:

# Append to overlay
append_pe_data("original.exe", "overlay_modified.exe", b"MyExtraData")

# Add as a new section
append_pe_data("original.exe", "section_modified.exe", b"MyExtraData", as_section=True, section_name=".mydata")
