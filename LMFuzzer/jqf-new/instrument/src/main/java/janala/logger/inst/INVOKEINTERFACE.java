package janala.logger.inst;

public class INVOKEINTERFACE extends Instruction implements InvokeInstruction {
  public String owner;
  public String name;
  public String desc;

  public INVOKEINTERFACE(int iid, int mid, String owner, String name, String desc) {
    super(iid, mid);
    this.owner = owner;
    this.name = name;
    this.desc = desc;
  }

  public void visit(IVisitor visitor) {
    visitor.visitINVOKEINTERFACE(this);
  }

  @Override
  public String toString() {
    return "INVOKEINTERFACE iid="
        + iid
        + " mid="
        + mid
        + " owner="
        + owner
        + " name="
        + name
        + " desc="
        + desc;
  }

  @Override
  public String getOwner() {
    return owner;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public String getDesc() {
    return desc;
  }
}
