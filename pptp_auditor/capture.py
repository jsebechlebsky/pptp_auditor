from scapy.sendrecv import sniff
from scapy.utils import PcapWriter
import threading


class PacketRecorder():

    def __init__(self, target, file):
        self.target = target
        self.file = file
        self._filter = 'host {0}'.format(target)
        self._stop_event = threading.Event()
        self._recorder_thread = threading.Thread(target=self._recorder_thread_func)
        self._pcap_writer = PcapWriter(file)

    def start(self):
        self._recorder_thread.start()

    def _recorder_thread_func(self):
        while not self._stop_event.isSet():
            pkts = sniff(stop_filter=lambda pkt: self._stop_event.isSet(),
                         filter=self._filter, timeout=1)
            self._pcap_writer.write(pkts)

    def stop(self):
        self._stop_event.set()
        self._recorder_thread.join()