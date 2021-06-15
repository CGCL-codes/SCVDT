static int __init xfrm6_tunnel_init(void)
{
	int rv;

	xfrm6_tunnel_spi_kmem = kmem_cache_create("xfrm6_tunnel_spi",
						  sizeof(struct xfrm6_tunnel_spi),
						  0, SLAB_HWCACHE_ALIGN,
						  NULL);
	if (!xfrm6_tunnel_spi_kmem)
		return -ENOMEM;
	rv = register_pernet_subsys(&xfrm6_tunnel_net_ops);
	if (rv < 0)
		goto out_pernet;
	rv = xfrm_register_type(&xfrm6_tunnel_type, AF_INET6);
	if (rv < 0)
		goto out_type;
	rv = xfrm6_tunnel_register(&xfrm6_tunnel_handler, AF_INET6);
	if (rv < 0)
		goto out_xfrm6;
	rv = xfrm6_tunnel_register(&xfrm46_tunnel_handler, AF_INET);
	if (rv < 0)
		goto out_xfrm46;
	return 0;

out_xfrm46:
	xfrm6_tunnel_deregister(&xfrm6_tunnel_handler, AF_INET6);
out_xfrm6:
	xfrm_unregister_type(&xfrm6_tunnel_type, AF_INET6);
out_type:
	unregister_pernet_subsys(&xfrm6_tunnel_net_ops);
out_pernet:
	kmem_cache_destroy(xfrm6_tunnel_spi_kmem);
	return rv;
}
