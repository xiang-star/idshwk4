@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string) {
    SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("responseUnique404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}

event zeek_init() {
    local r_All = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
    local r_404 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM));
    local r_Unique404 = SumStats::Reducer($stream="responseUnique404", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="idshwk4", $epoch=10min, $reducers=set(r_All, r_404, r_Unique404), $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
        local rs1 = result["response"];
        local rs2 = result["response404"];
        local rs3 = result["responseUnique404"];
        if (rs2$sum > 2) {
            if (rs2$sum / rs1$sum > 0.2) {
                if (rs3$unique / rs2$sum > 0.5) {
                    print fmt(" %s is a scanner with %.0f scan attemps on %d urls", key$host, rs2$sum, rs3$unique);
                } 
            }
        }
    }]);
}
