import itertools
import mimetypes
import io
import os

from django.http import HttpResponse,StreamingHttpResponse
from django.utils.http import content_disposition_header

def filereaderfactory(filein,block_size):
    def _filereader():
        return filein.read(block_size)

    return _filereader

class MultiFileSegmentsResponse(StreamingHttpResponse):
    """
    A streaming HTTP response class optimized for a file which is consisted with multi file segments..
    """

    block_size = 4096

    def __init__(self, *args, as_attachment=False, filename="", **kwargs):
        self.as_attachment = as_attachment
        self.filename = filename
        self._no_explicit_content_type = (
            "content_type" not in kwargs or kwargs["content_type"] is None
        )
        super().__init__(*args, **kwargs)

    def _set_streaming_content(self, files):
        streams = []
        self.files = files
        for file in files:
            filein = open(file,'rb')
            self._resource_closers.append(filein.close)
            streams.append(filein)

        self.set_headers(streams)
        super()._set_streaming_content(itertools.chain(*[iter(filereaderfactory(filein,self.block_size), b"") for filein in streams]))

    def set_headers(self, streams):
        """
        Set some common response headers (Content-Length, Content-Type, and
        Content-Disposition) based on the `filelike` response content.
        """
        content_length = 0
        for i in range(len(streams)):
            filelike = streams[i]
            filename = self.files[i]
            seekable = hasattr(filelike, "seek") and (
                not hasattr(filelike, "seekable") or filelike.seekable()
            )
            if hasattr(filelike, "tell"):
                if seekable:
                    initial_position = filelike.tell()
                    filelike.seek(0, io.SEEK_END)
                    content_length += filelike.tell() - initial_position
                    filelike.seek(initial_position)
                elif hasattr(filelike, "getbuffer"):
                    content_length  += filelike.getbuffer().nbytes - filelike.tell()
                elif os.path.exists(filename):
                    content_length += os.path.getsize(filename) - filelike.tell()
            elif seekable:
                length += sum(iter(lambda: len(filelike.read(self.block_size)), 0))
                content_length += length
                filelike.seek(-1 * length, io.SEEK_END)
        self.headers["Content-Length"] = (content_length)
        filename = os.path.basename(self.filename or filename)
        if self._no_explicit_content_type:
            if filename:
                content_type, encoding = mimetypes.guess_type(filename)
                # Encoding isn't set to prevent browsers from automatically
                # uncompressing files.
                content_type = {
                    "bzip2": "application/x-bzip",
                    "gzip": "application/gzip",
                    "xz": "application/x-xz",
                }.get(encoding, content_type)
                self.headers["Content-Type"] = (
                    content_type or "application/octet-stream"
                )
            else:
                self.headers["Content-Type"] = "application/octet-stream"

        if content_disposition := content_disposition_header(
            self.as_attachment, filename
        ):
            self.headers["Content-Disposition"] = content_disposition

