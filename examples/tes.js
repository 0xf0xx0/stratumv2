function updateProbabilities(hashrate, unit) {
    let options = {"network_hash_rate":"2000.0","blocks_per_day":"72","block_time":"20","network_difficulty":2000000000.0,"btc_price":80048};
    let blockTime = options.block_time * 60;
    let blocksPerDay = options.blocks_per_day;
    let networkHashrate = parseFloat(
        String(options.network_hash_rate).replace(/,/g, ""),
    );
    let networkHashrateTH = networkHashrate * 1e6;
    let networkDifficulty = parseFloat(options.network_difficulty);
    if (!hashrate) {
        return;
    }
    if (isNaN(hashrate)) {
        if (!error) {
            alert("Hashrate field must have a number.");
            error = !0;
        }
        return;
    } else {
        error = !1;
    }
    hashrate = parseFloat(hashrate);
    let conversion = {
        "MH/s": 1e-6,
        "GH/s": 1e-3,
        "TH/s": 1,
        "PH/s": 1e3,
        "EH/s": 1e6,
    };
    let hashrateConversion = hashrate * conversion[unit];
    let hashrateHs = hashrateConversion * 1e12;
    let timeEstimateSeconds =
        (networkDifficulty * Math.pow(2, 32)) / hashrateHs;
    let timeEstimateDays = timeEstimateSeconds / (60 * 60 * 24);
    let timeEstimateYears = timeEstimateDays / 365.25;
    let probabilityPerBlock = blockTime / timeEstimateSeconds;
    let probabilityPerDay =
        1 - Math.pow(1 - probabilityPerBlock, blocksPerDay);
    let probabilityPerWeek = 1 - Math.pow(1 - probabilityPerDay, 7);
    let probabilityPerMonth = 1 - Math.pow(1 - probabilityPerDay, 30);
    let probabilityPerYear = 1 - Math.pow(1 - probabilityPerDay, 365.25);
    const oddsPerBlock =
        probabilityPerBlock > 0
            ? `1 in ${Math.round(1 / probabilityPerBlock).toLocaleString()}`
            : "N/A";
    const oddsPerDay =
        probabilityPerDay > 0
            ? `1 in ${Math.round(1 / probabilityPerDay).toLocaleString()}`
            : "N/A";
    const oddsPerMonth =
        probabilityPerMonth > 0
            ? `1 in ${Math.round(1 / probabilityPerMonth).toLocaleString()}`
            : "N/A";
    const oddsPerYear =
        probabilityPerYear > 0
            ? `1 in ${Math.round(1 / probabilityPerYear).toLocaleString()}`
            : "N/A";
    console.log(`day: ${oddsPerDay}\nblock: ${oddsPerBlock}`)
}
updateProbabilities(111, "TH/s")
