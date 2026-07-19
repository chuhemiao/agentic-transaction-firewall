// A mandate that was not human-authorized must never execute, no matter
// what any `permit` policy says — Cedar always applies `forbid` last
// (PRD §11.3.1).
forbid (
    principal,
    action,
    resource
)
when {
    context.human_authorized == false
};
