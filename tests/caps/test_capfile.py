import pytest

from caps.capfile import CapReader, CapWriter


@pytest.fixture
def temp_cap_file(tmpdir):
    return tmpdir.join("temp_cap.cap").strpath


@pytest.mark.parametrize(("gz"), [True, False],
                         ids=["compressed", "regular"])
@pytest.mark.parametrize(("endianness"), [">", "<", ""],
                         ids=["big-endian", "little-endian", "default-enidan"])
@pytest.mark.parametrize(("sync"), [True, False],
                         ids=["sync", "no-sync"])
def test_cap_write_read(temp_cap_file, gz, endianness, sync):
    cap_writer = CapWriter(temp_cap_file, gz=gz,
                           endianness=endianness, sync=sync)

    # write 3 dummy packets.
    cap_writer.write("A")
    cap_writer.write("B")
    cap_writer.write("C")

    # close the cap writer.
    cap_writer.close()

    cap_reader = CapReader(temp_cap_file)
    packets = cap_reader.read_all_packets()
    assert packets == ["A", "B", "C"]
    cap_reader.close()


@pytest.mark.parametrize(("gz"), [True, False],
                         ids=["compressed", "regular"])
@pytest.mark.parametrize(("endianness"), [">", "<", ""],
                         ids=["big-endian", "little-endian", "default-enidan"])
@pytest.mark.parametrize(("sync"), [True, False],
                         ids=["sync", "no-sync"])
def  test_cap_write_append_read(temp_cap_file, gz, endianness, sync):
    cap_writer = CapWriter(temp_cap_file, gz=gz,
                           endianness=endianness, sync=sync)
    cap_writer.write("A")
    cap_writer.write("B")
    cap_writer.close()

    cap_writer2 = CapWriter(temp_cap_file, gz=gz,
                           endianness=endianness, sync=sync,
                           append=True)
    cap_writer2.write("C")
    cap_writer2.write("D")
    cap_writer2.close()

    cap_reader = CapReader(temp_cap_file)
    packets = cap_reader.read_all_packets()
    assert packets == ["A", "B", "C", "D"]
    cap_reader.close()


def test_cap_reader_reset(temp_cap_file):
    cap_writer = CapWriter(temp_cap_file)
    cap_writer.write("A")
    cap_writer.write("B")
    cap_writer.close()

    cap_reader = CapReader(temp_cap_file)
    assert cap_reader.read_all_packets() == ["A", "B"]
    assert cap_reader.read_all_packets() == ["A", "B"]
