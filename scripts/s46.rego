	package opsmx
	import future.keywords.in

	default exception_list = []
	default exception_count = 0

	policy_name = input.metadata.policyName
	policy_category = replace(input.metadata.policyCategory, " ", "_")
	exception_list = input.metadata.exception[policy_category]

	missing(obj, field) {
		not obj[field]
	}

	missing(obj, field) {
		obj[field] == ""
	}

	canonify_cpu(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		endswith(orig, "m")
		new := to_number(replace(orig, "m", ""))
	}

	canonify_cpu(orig) = new {
		not is_number(orig)
		not endswith(orig, "m")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", orig,-1)
		new := to_number(orig) * 1000
	}

	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000

	# 10 ** 18
	mem_multiple("P") = 1000000000000000000

	# 10 ** 15
	mem_multiple("T") = 1000000000000000

	# 10 ** 12
	mem_multiple("G") = 1000000000000

	# 10 ** 9
	mem_multiple("M") = 1000000000

	# 10 ** 6
	mem_multiple("k") = 1000000

	# 10 ** 3
	mem_multiple("") = 1000

	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741

	# 10 ** 0
	mem_multiple("m") = 1

	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000

	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000

	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000

	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000

	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000

	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000

	get_suffix(mem) = suffix {
		not is_string(mem)
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 0
		suffix := substring(mem, count(mem) - 1, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		suffix := substring(mem, count(mem) - 2, -1)
		mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		not mem_multiple(substring(mem, count(mem) - 2, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		suffix := ""
	}

	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 0
		suffix := ""
	}

	canonify_mem(orig) = new {
		is_number(orig)
		new := orig * 1000
	}

	canonify_mem(orig) = new {
		not is_number(orig)
		suffix := get_suffix(orig)
		raw := replace(orig, suffix, "")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
		new := to_number(raw) * mem_multiple(suffix)
	}

	# Ephemeral containers not checked as it is not possible to set field.

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "containers"}]
		policy_name in exception_list
		alertStatus := "exception"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": "", "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		not policy_name in exception_list
		alertStatus := "active"
	}

	deny[{"alertMsg": msg, "suggestion": "Suggest to check the resource limits set and optimize them.", "error": "", "exception": policy_name, "alertStatus": alertStatus}] {
		general_violation[{"msg": msg, "field": "initContainers"}]
		not policy_name in exception_list
		alertStatus := "exception"
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		not canonify_cpu(cpu_orig)
		msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		not canonify_mem(mem_orig)
		msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources.limits
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "cpu")
		msg := sprintf("container <%v> has no cpu limit", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "memory")
		msg := sprintf("container <%v> has no memory limit", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		cpu := canonify_cpu(cpu_orig)
		max_cpu_orig := input.parameters.cpu
		max_cpu := canonify_cpu(max_cpu_orig)
		cpu > max_cpu
		msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed of <%v>", [container.name, cpu_orig, max_cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		mem := canonify_mem(mem_orig)
		max_mem_orig := input.parameters.memory
		max_mem := canonify_mem(max_mem_orig)
		mem > max_mem
		msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed of <%v>", [container.name, mem_orig, max_mem_orig])
	}
