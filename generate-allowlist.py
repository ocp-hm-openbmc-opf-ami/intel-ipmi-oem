#!/usr/bin/env python3

import re
import sys


def usage():
    sys.stderr.write("Usage: $0 allowlist-config-in allowlist-header-out\n")
    sys.stderr.write("    Reads in allowlist config, sorting the contents\n")
    sys.stderr.write("    and outputs a header file\n")
    sys.exit(-1)


class Error(Exception):
    pass


class DuplicateEntry(Error):
    def __init__(self, e):
        super(Error, self).__init__(
            "Multiple entries with matching netfn/cmd found ({})".format(e)
        )


class ParseError(Error):
    def __init__(self, d):
        super(Error, self).__init__("Parse error at: '{}'".format(d))


class entry:
    linere = re.compile(
        r"(0x[0-9a-f]{2}):(0x[0-9a-f]{2})((:(0x[0-9a-f]{4}))?)\s*((//\s*(.*))?)",  # noqa: E501
        re.I,
    )

    def __init__(self, data):
        # parse data line into values:
        # type 1, two values: netfn, cmd
        # type 2, three values: netfn, cmd, channels
        try:
            m = self.linere.fullmatch(data).groups()
        except Exception:
            raise ParseError(data)
        self.netfn = int(m[0], 16)
        self.cmd = int(m[1], 16)
        if m[4] is not None:
            self.channels = int(m[4], 16)
        else:
            # if no channel was provided, default to previous behavior, which
            # is allow all interfaces, including the system interface (ch 15)
            self.channels = 0xFFFF
        if m[6] is not None:
            self.comment = "// " + m[7]
        else:
            self.comment = "//"

    def __str__(self):
        global selected_file
        if selected_file != "ipmi-blocklist.hpp":
            return " ".join(
                [
                    "{",
                    "0x{0.netfn:02x},".format(self),
                    "0x{0.cmd:02x},".format(self),
                    "0x{0.channels:04x}".format(self),
                    "},",
                    "{0.comment}".format(self),
                ]
            )
        else:
            return " ".join(
                [
                    "{",
                    "0x{0.netfn:02x},".format(self),
                    "0x{0.cmd:02x}".format(self),
                    "},",
                    "{0.comment}".format(self),
                ]
            )

    def __lt__(self, other):
        if self.netfn == other.netfn:
            return self.cmd < other.cmd
        return self.netfn < other.netfn

    def match(self, other):
        return (self.netfn == other.netfn) and (self.cmd == other.cmd)


def parse(config):
    entries = []
    with open(config) as f:
        for line in f:
            line = line.strip()
            if len(line) == 0 or line[0] == "#":
                continue
            e = entry(line)
            if any([e.match(item) for item in entries]):
                d = DuplicateEntry(e)
                sys.stderr.write("WARNING: {}\n".format(d))
            else:
                entries.append(e)
    entries.sort()
    return entries


def output(entries, hppfile):
    lines = [
        "#pragma once",
        "",
        "// AUTOGENERATED FILE; DO NOT MODIFY",
        "",
        "#include <array>",
        "#include <tuple>",
        "",
        (
            "using netfncmd_tuple = std::tuple<unsigned char, unsigned char,"
            " unsigned short>;"
        ),
        "",
    ]
    lines_blklist = [
        "#pragma once",
        "",
        "// AUTOGENERATED FILE; DO NOT MODIFY",
        "",
        "#include <array>",
        "#include <tuple>",
        "",
        "using netfncmds_tuple = std::tuple<unsigned char, unsigned char>;"
        "",
    ]
    if hppfile == "ipmi-allowlist.hpp":
        lines.append("constexpr const std::array<netfncmd_tuple, {}> allowlist = ".format(len(entries)))
    elif hppfile == "ipmi-systemlock.hpp":
        lines.append("constexpr const std::array<netfncmd_tuple, {}> setallowlist = ".format(len(entries)))
    elif hppfile == "ipmi-blocklist.hpp":
        lines_blklist.append("constexpr const std::array<netfncmds_tuple, {}> blocklist = ".format(len(entries)))

    if hppfile == "ipmi-blocklist.hpp":
        lines_blklist.append("{{")
        lines_blklist.extend(["    {}".format(e) for e in entries])
        lines_blklist.append("}};\n")
        with open(hppfile, "w") as hppb:
             hppb.write("\n".join(lines_blklist))
    else:
      lines.append("{{")
      lines.extend(["    {}".format(e) for e in entries])
      lines.append("}};\n")
      with open(hppfile, "w") as hpp:
            hpp.write("\n".join(lines))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
    config = sys.argv[1]
    header = sys.argv[2]
    selected_file = header
    entries = parse(config)
    output(entries, header)
