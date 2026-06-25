import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

SRC="EXEC CICS SEND MAP('M1') END-EXEC. EXEC CICS LINK PROGRAM('PROG2') COMMAREA(WS) END-EXEC. EXEC CICS RETURN TRANSID('TR01') END-EXEC."
def test_parse():
    p=server.parse_cics(SRC); assert "SEND" in p.exec_commands; assert p.uses_commarea; assert "PROG2" in p.programs_called
def test_govern():
    assert any("SOX" in f for f in server.govern_cics(SRC).frameworks)
