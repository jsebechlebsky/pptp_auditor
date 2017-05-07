from scapy.sendrecv import sniff
from scapy.utils import PcapWriter
import threading


class PacketRecorder:
    """
    Simple class providing pcap packet recording
    running in separate thread
    """

    def __init__(self, _target, _file):
        """
        Initialize pcap packet recorder

        :param _target: IP address of the target
        :param _file: pcap file name
        """
        self.target = _target
        self.file = _file
        self._filter = 'host {0}'.format(_target)
        self._stop_event = threading.Event()
        self._recorder_thread = threading.Thread(target=self._recorder_thread_func)
        self._pcap_writer = PcapWriter(file)

    def start(self):
        """Start recording"""
        self._recorder_thread.start()

    def _recorder_thread_func(self):
        while not self._stop_event.isSet():
            pkts = sniff(stop_filter=lambda pkt: self._stop_event.isSet(),
                         filter=self._filter, timeout=1)
            self._pcap_writer.write(pkts)

    def stop(self):
        """Stop recording"""
        self._stop_event.set()
        self._recorder_thread.join()