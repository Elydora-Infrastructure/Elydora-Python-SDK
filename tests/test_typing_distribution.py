from importlib.resources import files


def test_package_declares_inline_type_information() -> None:
    marker = files("elydora").joinpath("py.typed")

    assert marker.is_file()
    assert marker.read_text(encoding="utf-8").strip() == ""
