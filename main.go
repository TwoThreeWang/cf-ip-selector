package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"github.com/joho/godotenv"
)

// IPResult 存储 IP 和它的测试延迟
type IPResult struct {
	IP      string
	Latency time.Duration
}

func main() {
	// 1. 加载环境变量
	err := godotenv.Load()
	if err != nil {
		log.Println("未找到 .env 文件，将尝试读取系统环境变量")
	}

	intervalStr := os.Getenv("INTERVAL_SECONDS")
	interval, _ := strconv.Atoi(intervalStr)
	if interval <= 0 {
		interval = 3600 // 默认1小时
	}

	log.Printf("程序启动，每隔 %d 秒运行一次...", interval)

	// 立即运行一次
	runTask()

	// 定时运行
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		runTask()
	}
}

func runTask() {
	log.Println("------ 开始新一轮优选 ------")

	// 1. 获取所有候选 IP
	sourceDomains := strings.Split(os.Getenv("SOURCE_DOMAINS"), ",")
	candidateIPs := getIPsFromDomains(sourceDomains)
	log.Printf("从域名中解析去重后共获得 %d 个 IP", len(candidateIPs))

	if len(candidateIPs) == 0 {
		log.Println("未获取到任何 IP，跳过本次执行")
		return
	}

	// 2. 并发测速 (TCP Latency)
	results := testIPSpeed(candidateIPs)
	log.Printf("有效响应的 IP 数量: %d", len(results))

	if len(results) == 0 {
		log.Println("所有 IP 均无法连接，跳过")
		return
	}

	// 3. 排序取前 10
	sort.Slice(results, func(i, j int) bool {
		return results[i].Latency < results[j].Latency
	})

	topCount := 10
	if len(results) < topCount {
		topCount = len(results)
	}
	bestIPs := results[:topCount]

	log.Println("Top 10 优选 IP:")
	var bestIPStrings []string
	for _, res := range bestIPs {
		fmt.Printf("IP: %s, 延迟: %v\n", res.IP, res.Latency)
		bestIPStrings = append(bestIPStrings, res.IP)
	}

	// 4. 更新 Cloudflare
	err := updateCloudflareDNS(bestIPStrings)
	if err != nil {
		log.Printf("Cloudflare 更新失败: %v", err)
		sendBarkNotification("Cloudflare 优选 IP 更新失败", err.Error())
		return
	}

	// 5. 发送通知
	msg := fmt.Sprintf("成功更新 %d 个优选 IP\n平均延迟: %v", len(bestIPStrings), bestIPs[0].Latency)
	sendBarkNotification("Cloudflare 优选 IP 已更新", msg)
	log.Println("------ 本轮结束 ------")
}

// getIPsFromDomains 解析域名获取 IP 并去重
func getIPsFromDomains(domains []string) []string {
	uniqueIPs := make(map[string]struct{})
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		cancel()
		if err != nil {
			log.Printf("解析域名 %s 失败: %v", domain, err)
			continue
		}
		for _, addr := range ips {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				uniqueIPs[ipv4.String()] = struct{}{}
			}
		}
	}

	var list []string
	for ip := range uniqueIPs {
		list = append(list, ip)
	}
	return list
}

// testIPSpeed 并发测试 IP 延迟 (TCP :443)
func testIPSpeed(ips []string) []IPResult {
	var results []IPResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 限制并发数为 50，防止句柄耗尽或被防火墙拦截
	semaphore := make(chan struct{}, 50)
	timeout := 2 * time.Second

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取令牌
			defer func() { <-semaphore }() // 释放令牌

			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, "443"), timeout)
			if err == nil {
				latency := time.Since(start)
				conn.Close()

				mu.Lock()
				results = append(results, IPResult{
					IP:      targetIP,
					Latency: latency,
				})
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return results
}

// updateCloudflareDNS 更新 Cloudflare DNS 记录
func updateCloudflareDNS(bestIPs []string) error {
	apiToken := strings.TrimSpace(os.Getenv("CF_API_TOKEN"))
	apiKey := strings.TrimSpace(os.Getenv("CF_API_KEY"))
	apiEmail := strings.TrimSpace(os.Getenv("CF_API_EMAIL"))
	zoneIDEnv := strings.TrimSpace(os.Getenv("CF_ZONE_ID"))
	targetDomain := strings.TrimSpace(os.Getenv("CF_TARGET_DOMAIN"))

	var missing []string
	if targetDomain == "" {
		missing = append(missing, "CF_TARGET_DOMAIN")
	}
	if zoneIDEnv == "" {
		missing = append(missing, "CF_ZONE_ID")
	}
	if apiToken == "" && (apiKey == "" || apiEmail == "") {
		missing = append(missing, "CF_API_TOKEN 或 CF_API_KEY/CF_API_EMAIL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("缺少或为空的环境变量: %s", strings.Join(missing, ", "))
	}

	var (
		api        *cloudflare.API
		err        error
		clientType string
	)
	if apiToken != "" {
		api, err = cloudflare.NewWithAPIToken(apiToken)
		clientType = "token"
	} else {
		api, err = cloudflare.New(apiKey, apiEmail)
		clientType = "key"
	}
	if err != nil {
		return err
	}

	zoneID := zoneIDEnv

	// 获取目标域名的所有现有 A 记录
	// 注意：这里我们只管理 A 记录 (IPv4)
	records, _, err := api.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: targetDomain,
		Type: "A",
	})
	if err != nil {
		if clientType == "token" && apiKey != "" && apiEmail != "" {
			msg := err.Error()
			if strings.Contains(msg, "Authentication error") || strings.Contains(msg, "Unable to authenticate request") || strings.Contains(msg, "Invalid request headers") {
				api, err = cloudflare.New(apiKey, apiEmail)
				if err != nil {
					return err
				}
				records, _, err = api.ListDNSRecords(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
					Name: targetDomain,
					Type: "A",
				})
				if err != nil {
					return fmt.Errorf("获取现有 DNS 记录失败: %v", err)
				}
			} else {
				return fmt.Errorf("获取现有 DNS 记录失败: %v", err)
			}
		} else {
			return fmt.Errorf("获取现有 DNS 记录失败: %v", err)
		}
	}

	// 构建“目标优选 IP”集合，用于快速判断是否在目标集
	bestSet := make(map[string]struct{}, len(bestIPs))
	for _, ip := range bestIPs {
		bestSet[ip] = struct{}{}
	}
	// 构建“现有 DNS 记录”索引，键为记录内容(IP)
	existingSet := make(map[string]cloudflare.DNSRecord, len(records))
	for _, r := range records {
		existingSet[r.Content] = r
	}
	var presentCount int
	for ip := range bestSet {
		if _, ok := existingSet[ip]; ok {
			presentCount++
		}
	}
	// 并发新增缺失的目标 IP 记录
	var wg sync.WaitGroup
	createErrChan := make(chan error, len(bestIPs))
	var mu sync.Mutex
	// 记录成功新增的 IP
	created := make(map[string]bool)
	addCount := 0 // 将要新增的数量，仅用于日志
	for _, ip := range bestIPs {
		if _, ok := existingSet[ip]; ok {
			// 已存在则跳过，避免重复创建
			continue
		}
		addCount++
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()
			_, err := api.CreateDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
				Type:    "A",
				Name:    targetDomain,
				Content: ipAddr,
				TTL:     60,
				Proxied: cloudflare.BoolPtr(false),
			})
			if err != nil {
				createErrChan <- fmt.Errorf("添加记录 %s 失败: %v", ipAddr, err)
				return
			}
			mu.Lock()
			created[ipAddr] = true
			mu.Unlock()
		}(ip)
	}
	log.Printf("正在添加 %d 条新记录...", addCount)
	wg.Wait()
	close(createErrChan)
	// 累加：已存在 + 新增成功 的目标记录数量
	presentCount += len(created)
	if presentCount == 0 {
		// 安全保护：若没有任何目标记录存在或新增成功，则不做删除，避免记录被清空
		if len(createErrChan) > 0 {
			return <-createErrChan
		}
		return fmt.Errorf("未成功添加任何新记录，已保留旧记录")
	}
	// 计算需要删除的旧记录：不在目标集合中的记录
	toDelete := make([]string, 0, len(records))
	for _, r := range records {
		if _, ok := bestSet[r.Content]; !ok {
			toDelete = append(toDelete, r.ID)
		}
	}
	// 并发删除旧记录
	deleteErrChan := make(chan error, len(toDelete))
	log.Printf("正在删除 %d 条旧记录...", len(toDelete))
	for _, id := range toDelete {
		wg.Add(1)
		go func(recordID string) {
			defer wg.Done()
			err := api.DeleteDNSRecord(context.Background(), cloudflare.ZoneIdentifier(zoneID), recordID)
			if err != nil {
				deleteErrChan <- fmt.Errorf("删除记录失败: %v", err)
			}
		}(id)
	}
	wg.Wait()
	close(deleteErrChan)

	// 检查是否有错误
	if len(createErrChan) > 0 {
		// 这里只打印第一个错误，实际应该收集所有
		return <-createErrChan
	}
	if len(deleteErrChan) > 0 {
		return <-deleteErrChan
	}

	log.Println("Cloudflare DNS 更新完成")
	return nil
}

// sendBarkNotification 发送 Bark 通知
func sendBarkNotification(title, body string) {
	barkURL := strings.TrimSpace(os.Getenv("BARK_URL"))
	if barkURL == "" {
		log.Println("未配置 Bark URL，跳过通知")
		return
	}

	// 简单的 GET 请求拼接
	// 格式: url/title/body
	if !strings.HasSuffix(barkURL, "/") {
		barkURL += "/"
	}

	titleEsc := url.PathEscape(title)
	bodyEsc := url.PathEscape(body)
	urlStr := fmt.Sprintf("%s%s/%s?group=CF优选", barkURL, titleEsc, bodyEsc)

	resp, err := http.Get(urlStr)
	if err != nil {
		log.Printf("Bark 推送失败: %v", err)
		return
	}
	defer resp.Body.Close()
}
