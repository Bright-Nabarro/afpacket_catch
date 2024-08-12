function get_bpf_filter(expr)
    local prgOutput = io.popen("tcpdump -dd "..expr.." 2>/dev/null")
    local context = prgOutput:read("a")
    prgOutput:close()
    local result = {}
    local matchAtLeastOnce = false
    local retLinesCount = 0
    
    for codeStr, jtStr, jfStr, kStr in
        context:gmatch("{%s*0[xX](%x+),%s*(%d+),%s*(%d+),%s*0[xX](%x+)%s*}")
    do
        matchAtLeastOnce = true
        if not (codeStr and jtStr and jfStr and kStr) then
            return nil
        end

        local code = tonumber(codeStr, 16)
        local jt = tonumber(jtStr, 10)
        local jf = tonumber(jfStr, 10)
        local k = tonumber(kStr, 16)
        -- 如果有一个为空，则直接返回空
        if not (code and jt and jf and k )then
            return nil
        end
        
        local entry = { code = code, jt = jt, jf = jf, k = k, }
        table.insert(result, entry)
        retLinesCount += 1
    end

    if (not matchAtLeastOnce) then
        return nil
    end

    return retLinesCount, result
end
