diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 8fc4de0d22b4..437b57068cf8 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -497,13 +497,14 @@ void giveup_all(struct task_struct *tsk)
 	if (!tsk->thread.regs)
 		return;
 
+	check_if_tm_restore_required(tsk);
+
 	usermsr = tsk->thread.regs->msr;
 
 	if ((usermsr & msr_all_available) == 0)
 		return;
 
 	msr_check_and_set(msr_all_available);
-	check_if_tm_restore_required(tsk);
 
 	WARN_ON((usermsr & MSR_VSX) && !((usermsr & MSR_FP) && (usermsr & MSR_VEC)));
 
