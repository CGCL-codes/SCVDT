diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 437b57068cf8..7a84c9f1778e 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -101,21 +101,8 @@ static void check_if_tm_restore_required(struct task_struct *tsk)
 	}
 }
 
-static bool tm_active_with_fp(struct task_struct *tsk)
-{
-	return MSR_TM_ACTIVE(tsk->thread.regs->msr) &&
-		(tsk->thread.ckpt_regs.msr & MSR_FP);
-}
-
-static bool tm_active_with_altivec(struct task_struct *tsk)
-{
-	return MSR_TM_ACTIVE(tsk->thread.regs->msr) &&
-		(tsk->thread.ckpt_regs.msr & MSR_VEC);
-}
 #else
 static inline void check_if_tm_restore_required(struct task_struct *tsk) { }
-static inline bool tm_active_with_fp(struct task_struct *tsk) { return false; }
-static inline bool tm_active_with_altivec(struct task_struct *tsk) { return false; }
 #endif /* CONFIG_PPC_TRANSACTIONAL_MEM */
 
 bool strict_msr_control;
@@ -252,7 +239,7 @@ EXPORT_SYMBOL(enable_kernel_fp);
 
 static int restore_fp(struct task_struct *tsk)
 {
-	if (tsk->thread.load_fp || tm_active_with_fp(tsk)) {
+	if (tsk->thread.load_fp) {
 		load_fp_state(&current->thread.fp_state);
 		current->thread.load_fp++;
 		return 1;
@@ -334,8 +321,7 @@ EXPORT_SYMBOL_GPL(flush_altivec_to_thread);
 
 static int restore_altivec(struct task_struct *tsk)
 {
-	if (cpu_has_feature(CPU_FTR_ALTIVEC) &&
-		(tsk->thread.load_vec || tm_active_with_altivec(tsk))) {
+	if (cpu_has_feature(CPU_FTR_ALTIVEC) && (tsk->thread.load_vec)) {
 		load_vr_state(&tsk->thread.vr_state);
 		tsk->thread.used_vr = 1;
 		tsk->thread.load_vec++;
