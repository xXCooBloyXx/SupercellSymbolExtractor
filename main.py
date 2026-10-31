import os
import sys

from utils import ByteStream

MH_MAGIC_64 = b"\xCF\xFA\xED\xFE"
MH_CIGAM_64 = b"\xFE\xED\xFA\xCF"

LC_REQ_DYLD = 0x80000000
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD

EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

def main(fileName):
	stream = ByteStream(open(fileName, "rb").read())

	magic = stream.readBytes(4)
	if magic == MH_CIGAM_64:
		stream.endian = "big"
	elif magic != MH_MAGIC_64:
		raise NotImplementedError("Only 64-bit Mach-O files are supported")

	stream.offset += 3 * 4
	ncmds = stream.readUInt32()
	stream.offset += 3 * 4

	for _ in range(ncmds):
		commandOffset = stream.offset
		cmd = stream.readUInt32()
		cmdsize = stream.readUInt32()
		if cmd == LC_DYLD_INFO_ONLY:
			stream.offset += 8 * 4
			exportOffset = stream.readUInt32()
			exportEndOffset = exportOffset + stream.readUInt32()
			break
		stream.offset = commandOffset + cmdsize
	else:
		raise ValueError("Command LC_DYLD_INFO_ONLY is missing")

	nodes = []
	stream.offset = exportOffset
	while stream.offset < exportEndOffset:
		node = {
			"offset": stream.offset,
			"address": None,
			"children": []
		}
		
		terminalEndOffset = stream.readULEB128() + stream.offset
		if terminalEndOffset > stream.offset:
			flags = stream.readULEB128()
			if not flags & (EXPORT_SYMBOL_FLAGS_REEXPORT | EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER):
				node["address"] = stream.readULEB128()
		stream.offset = terminalEndOffset
		
		for _ in range(stream.readUInt8()):
			child = {}
			try:
				child["suffix"] = stream.readCString()
			except UnicodeDecodeError as error: # noqa: F841
				#print("Error:", error)
				child["suffix"] = "ERROR"
			child["offset"] = exportOffset + stream.readULEB128()
			node["children"].append(child)
		nodes.append(node)

	nodeOffsetToNode = {}
	childOffsets = set()
	for node in nodes:
		nodeOffsetToNode[node["offset"]] = node
		childOffsets.update(child["offset"] for child in node["children"])
	
	def processNode(node, prefix=""):
		if node["address"] is not None and prefix:
			symbols[node["address"]] = prefix
			
		for child in node["children"]:
			childNode = nodeOffsetToNode.get(child["offset"])
			if childNode is not None:
				processNode(childNode, prefix + child["suffix"])

	symbols = {}
	for node in nodes:
		if node["offset"] not in childOffsets:
			processNode(node)

	with open(f"{fileName}_symbols.txt", "w") as symbolsFile:
		symbolsFile.writelines(f"{hex(offset)} {name}\n" for offset, name in sorted(symbols.items(), key=lambda item: item[0]))

	print(f"Extracted {len(symbols)} symbols")

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print(f"Usage: {os.path.basename(__file__)} <file_name>")
		exit()
		
	main(sys.argv[1])