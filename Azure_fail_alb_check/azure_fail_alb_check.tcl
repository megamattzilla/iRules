when FLOW_INIT {
  if { [active_members http_pool] < 1 } {
    reject
  }
}