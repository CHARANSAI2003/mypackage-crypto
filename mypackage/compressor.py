import shutil
import os

def compress_folder(folder_path: str, out_file: str = None) -> str:
    """
    Compress a folder into a zip file.
    """
    if out_file is None:
        out_file = f"{folder_path}.zip"
    shutil.make_archive(base_name=folder_path, format='zip', root_dir=folder_path)
    return out_file

def decompress_file(zip_file: str, extract_to: str = None) -> str:
    """
    Decompress a zip file to the specified directory.
    """
    if extract_to is None:
        extract_to = os.path.splitext(zip_file)[0] + "_unzipped"
    shutil.unpack_archive(zip_file, extract_to)
    return extract_to
