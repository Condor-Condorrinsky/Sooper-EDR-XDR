import Evtx.Evtx as evtx
import Evtx.Views as e_views

def parse_evtx_to_xml(path_to_evtx: str) -> str:
    with evtx.Evtx(path_to_evtx) as log:
        strings = []
        recs = []
        strings.append(e_views.XML_HEADER)
        strings.append("<Events>")
        for record in log.records():
            recs.append(record.xml())
        recs_str = ''.join(recs)
        # strings.append(record.xml() for record in log.records()) - nie dziala
        strings.append(recs_str)
        strings.append("</Events>")
        ret = ''.join(strings)
    return ret

def dump_xmlstr_to_file(string_to_dump: str, filepath: str):
    with open(filepath, "w+") as xmlfile:
        xmlfile.write(string_to_dump)
