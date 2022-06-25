from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

COMMANDS = {
    0x89: "Calibrate",
    0x98: "CalibrateImage",
    0x08: "CfgDioIrq",
    0x07: "ClrError",
    0x02: "ClrIrqStatus",
    0x17: "GetError",
    0x12: "GetIrqStatus",
    0x14: "GetPacketStatus",
    0x11: "GetPacketType",
    0x15: "GetRssiInst",
    0x13: "GetRxBufferStatus",
    0x10: "GetStats",
    0xC0: "GetStatus",
    0x1E: "ReadBuffer",
    0x1D: "RegRegister",
    0x00: "ResetStats",
    0x8F: "SetBufferBaseAddress",
    0xC5: "SetCad",
    0x88: "SetCadParams",
    0xC1: "SetFs",
    0xA0: "SetLoRaSymbTimeout",
    0x8B: "SetModulationParams",
    0x8C: "SetPacketParams",
    0x8A: "SetPacketType",
    0x95: "SetPaConfig",
    0x96: "SetRegulatorMode",
    0x86: "SetRfFrequency",
    0x82: "SetRx",
    0x94: "SetRxDutyCycle",
    0x84: "SetSleep",
    0x80: "SetStandby",
    0x9F: "SetStopRxTimerOnPreamble",
    0x97: "SetTcxoMode",
    0x83: "SetTx",
    0xD2: "SetTxContinuousPreamble",
    0xD1: "SetTxContinuousWave",
    0x8E: "SetTxParams",
    0x93: "SetTxRxFallbackMode",
    0x0E: "WriteBuffer",
    0x0D: "WriteRegister",
}

REGISTERS = {
    # Generic bit synchronization.
    0x06AC: "GBSYNC",
    # Generic packet control.
    0x06B8: "GPKTCTL1A",
    # Generic whitening.
    0x06B9: "GWHITEINIRL",
    # Generic CRC initial.
    0x06BC: "GCRCINIRH",
    # Generic CRC polynomial.
    0x06BE: "GCRCPOLRH",
    # Generic synchronization word 7.
    0x06C0: "GSYNC7",
    # Node address.
    0x06CD: "NODE",
    # Broadcast address.
    0x06CE: "BROADCAST",
    # LoRa synchronization word MSB.
    0x0740: "LSYNCH",
    # LoRa synchronization word LSB.
    #[allow(dead_code)]
    0x0741: "LSYNCL",
    # Receiver gain control.
    0x08AC: "RXGAINC",
    # PA over current protection.
    0x08E7: "PAOCP",
    # RTC control.
    0x0902: "RTCCTLR",
    # RTC period MSB.
    0x0906: "RTCPRDR2",
    # RTC period mid-byte.
    #[allow(dead_code)]
    0x0907: "RTCPRDR1",
    # RTC period LSB.
    #[allow(dead_code)]
    0x0908: "RTCPRDR0",
    # HSE32 OSC_IN capacitor trim.
    0x0911: "HSEINTRIM",
    # HSE32 OSC_OUT capacitor trim.
    0x0912: "HSEOUTTRIM",
    # SMPS control 0.
    0x0916: "SMPSC0",
    # Power control.
    0x091A: "PC",
    # SMPS control 2.
    0x0923: "SMPSC2",
}

class SpiTransceiver(HighLevelAnalyzer):
    """
    Analzyer for the stm32wl transceiver protocol over SPI.
    """
    result_types = {
        "command": {
            "format": "{{data.cmd}}"
        },
        "error": {
            "format": "ERROR: {{data.error_info}}",
        }
    }

    def __init__(self):
        # Holds the individual SPI result frames that make up the transaction
        self.frames = []

        # Whether SPI is currently enabled
        self.spi_enable = False

        # Start time of the transaction - equivalent to the start time of the first data frame
        self.transaction_start_time = None

        # End time of the transaction - equivalent to the end time of the last data frame
        self.transaction_end_time = None

    def handle_enable(self, frame: AnalyzerFrame):
        self.frames = []
        self.spi_enable = True
        self.transaction_start_time = None
        self.transaction_end_time = None

    def reset(self):
        self.frames = []
        self.spi_enable = False
        self.transaction_start_time = None
        self.transaction_end_time = None

    def is_valid_transaction(self) -> bool:
        return self.spi_enable and (self.transaction_start_time is not None)

    def handle_result(self, frame):
        if self.spi_enable:
            if self.transaction_start_time is None:
                self.transaction_start_time = frame.start_time
            self.transaction_end_time = frame.end_time
            self.frames.append(frame)   

    def handle_disable(self, frame):
        if self.is_valid_transaction():
            transaction = self.get_frame_data()
            cmd = transaction["mosi"][0]
            result = AnalyzerFrame(
                "command",
                self.transaction_start_time,
                self.transaction_end_time,
                {"cmd": COMMANDS.get(cmd, "Unknown")},
            )
        else:
            result = AnalyzerFrame(
                "error",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Invalid SPI transaction (spi_enable={}, transaction_start_time={})".format(
                        self.spi_enable,
                        self.transaction_start_time,
                    )
                }
            )

        self.reset()
        return result

    def handle_error(self, frame):
        print("Received 'error' type from input analyzer")
        return

    def get_frame_data(self) -> dict:
        miso = bytearray()
        mosi = bytearray()

        for frame in self.frames:
            miso += frame.data["miso"]
            mosi += frame.data["mosi"]

        return {
            "miso": bytes(miso),
            "mosi": bytes(mosi),
        }

    def decode(self, frame: AnalyzerFrame):
        if frame.type == "enable":
            return self.handle_enable(frame)
        elif frame.type == "result":
            return self.handle_result(frame)
        elif frame.type == "disable":
            return self.handle_disable(frame)
        elif frame.type == "error":
            return self.handle_error(frame)
        else:
            return AnalyzerFrame(
                "error",
                frame.start_time,
                frame.end_time,
                {
                    "error_info": "Unexpected frame type from input analyzer: {}".format(frame.type)
                }
            )
