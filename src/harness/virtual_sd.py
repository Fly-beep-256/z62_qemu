"""Fresh run-local SD media for the original guest; never opens a real disk."""
import hashlib
from pathlib import Path
import struct


CAPACITY = 256 * 1024 * 1024
SECTOR = 512
PARTITION_START = 2048


def create(path, formatted=False, filesystem="FAT16", capacity_bytes=CAPACITY):
    if filesystem not in ("FAT16", "FAT32"):
        raise ValueError("Virtual media requires FAT16 or FAT32")
    if capacity_bytes not in (CAPACITY, 4 * 1024 * 1024 * 1024):
        raise ValueError("Virtual SD capacity must be256MiB or4GiB")
    if formatted and filesystem == "FAT16" and capacity_bytes != CAPACITY:
        raise ValueError("4GiB formatted virtual card requires FAT32")
    path = Path(path).resolve()
    with path.open("xb") as medium:
        medium.truncate(capacity_bytes)
        info = dict(path=str(path), capacity_bytes=capacity_bytes, created_exclusively=True,
                    initial_content=filesystem if formatted else "zero",
                    original_camera_data_supplied=False, physical_slot_mapping_verified=False)
        if not formatted:
            return info
        total_sectors = capacity_bytes // SECTOR - PARTITION_START
        fat32 = filesystem == "FAT32"
        sectors_per_cluster, reserved, root_entries = (4, 32, 0) if fat32 else (16, 1, 512)
        if fat32 and capacity_bytes > 2 * 1024 * 1024 * 1024:
            sectors_per_cluster = 8
        root_sectors = root_entries * 32 // SECTOR
        fat_sectors = 128
        if fat32:
            fat_sectors = 1
            for _ in range(20):
                clusters = (total_sectors - reserved - 2 * fat_sectors) // sectors_per_cluster
                required = ((clusters + 2) * 4 + SECTOR - 1) // SECTOR
                if required == fat_sectors:
                    break
                fat_sectors = required
        clusters = (total_sectors - reserved - 2 * fat_sectors - root_sectors) // sectors_per_cluster
        assert (65525 <= clusters < 0xffffff5) if fat32 else (4085 <= clusters < 65525)
        assert (clusters + 2) * (4 if fat32 else 2) <= fat_sectors * SECTOR
        mbr = bytearray(SECTOR)
        # Primary FAT16 partition; the original driver reads the LBA fields.
        struct.pack_into("<B3sB3sII", mbr, 446, 0x80, b"\xfe\xff\xff", 0x0c if fat32 else 0x06,
                         b"\xfe\xff\xff", PARTITION_START, total_sectors)
        mbr[510:512] = b"\x55\xaa"
        medium.seek(0)
        medium.write(mbr)
        boot = bytearray(SECTOR)
        boot[:11] = b"\xeb\x58\x90MSDOS5.0" if fat32 else b"\xeb\x3c\x90MSDOS5.0"
        struct.pack_into("<HBHBHHBHHHII", boot, 11, SECTOR, sectors_per_cluster,
                         reserved, 2, root_entries, 0, 0xf8, 0 if fat32 else fat_sectors, 63, 255,
                         PARTITION_START, total_sectors)
        if fat32:
            struct.pack_into("<IHHIHH", boot, 36, fat_sectors, 0, 0, 2, 1, 6)
            struct.pack_into("<BBBI", boot, 64, 0x80, 0, 0x29, 0x6c170001)
            boot[71:82] = b"Z6II_LAB   "
            boot[82:90] = b"FAT32   "
        else:
            struct.pack_into("<BBBI", boot, 36, 0x80, 0, 0x29, 0x6c170001)
            boot[43:54] = b"Z6II_LAB   "
            boot[54:62] = b"FAT16   "
        boot[510:512] = b"\x55\xaa"
        medium.seek(PARTITION_START * SECTOR)
        medium.write(boot)
        if fat32:
            medium.seek((PARTITION_START + 6) * SECTOR)
            medium.write(boot)
            fsinfo = bytearray(SECTOR)
            struct.pack_into("<I", fsinfo, 0, 0x41615252)
            struct.pack_into("<III", fsinfo, 484, 0x61417272, clusters - 1, 3)
            struct.pack_into("<I", fsinfo, 508, 0xaa550000)
            for index in (1, 7):
                medium.seek((PARTITION_START + index) * SECTOR)
                medium.write(fsinfo)
        fat = bytearray(fat_sectors * SECTOR)
        if fat32:
            struct.pack_into("<III", fat, 0, 0x0ffffff8, 0xffffffff, 0x0fffffff)
        else:
            struct.pack_into("<HH", fat, 0, 0xfff8, 0xffff)
        for copy in range(2):
            medium.seek((PARTITION_START + reserved + copy * fat_sectors) * SECTOR)
            medium.write(fat)
        root = bytearray((sectors_per_cluster if fat32 else root_sectors) * SECTOR)
        root[:11] = b"Z6II_LAB   "
        root[11] = 0x08
        medium.seek((PARTITION_START + reserved + 2 * fat_sectors) * SECTOR)
        medium.write(root)
        info.update(partition_start_LBA=PARTITION_START, partition_sectors=total_sectors,
                    sectors_per_cluster=sectors_per_cluster, FAT_sectors=fat_sectors,
                    cluster_count=clusters, initial_MBR_sha256=hashlib.sha256(mbr).hexdigest(),
                    initial_BPB_sha256=hashlib.sha256(boot).hexdigest(),
                    filesystem_is_synthetic=True, original_NCSET_supplied=False)
        return info
