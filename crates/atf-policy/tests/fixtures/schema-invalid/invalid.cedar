permit (
    principal,
    action == Action::"payment/purchase_api_resource",
    resource
)
when {
    context.organiztion_id == "alpha-lab"
};
