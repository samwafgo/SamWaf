package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/wafdb"
	"sync"
	"testing"
	"time"
)

// TestCreateIndexWithConcurrentOperations 测试在创建索引的同时进行读写操作
func TestCreateIndexWithConcurrentOperations(t *testing.T) {
	//初始化日志
	zlog.InitZLog(global.GWAF_RELEASE, "json")
	//初始化本地数据库
	wafdb.InitCoreDb("../")
	wafdb.InitLogDb("../")
	wafdb.InitStatsDb("../")

	// 确保数据库连接已初始化
	if global.GWAF_LOCAL_DB == nil || global.GWAF_LOCAL_LOG_DB == nil || global.GWAF_LOCAL_STATS_DB == nil {
		t.Skip("数据库连接未初始化，跳过测试")
	}

	var wg sync.WaitGroup
	// 用于标记测试是否通过
	success := true
	errChan := make(chan error, 10)

	// 启动索引创建任务
	wg.Add(1)
	go func() {
		defer wg.Done()
		t.Log("开始创建索引...")
		startTime := time.Now()

		// 执行索引创建
		TaskCreateIndex()

		duration := time.Since(startTime)
		t.Logf("索引创建完成，耗时: %s", duration.String())
	}()

	// 同时进行主库写入操作
	wg.Add(1)
	go func() {
		defer wg.Done()
		db := global.GWAF_LOCAL_DB
		if db == nil {
			errChan <- nil
			return
		}

		// 模拟多次写入操作
		for i := 0; i < 10; i++ {
			// 插入测试数据
			err := db.Exec("INSERT INTO ip_tags (user_code, tenant_id, ip, ip_tag) VALUES (?, ?, ?, ?)",
				"test_user", "test_tenant", "192.168.1."+time.Now().Format("15.04.05.000"), "test_tag_"+time.Now().Format("15.04.05.000")).Error
			if err != nil {
				t.Logf("主库写入失败: %v", err)
				errChan <- err
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Log("主库写入测试完成")
	}()

	// 同时进行主库读取操作
	wg.Add(1)
	go func() {
		defer wg.Done()
		db := global.GWAF_LOCAL_DB
		if db == nil {
			errChan <- nil
			return
		}

		// 模拟多次读取操作
		for i := 0; i < 10; i++ {
			var count int64
			err := db.Table("ip_tags").Where("user_code = ?", "test_user").Count(&count).Error
			if err != nil {
				t.Logf("主库读取失败: %v", err)
				errChan <- err
				return
			}
			t.Logf("主库读取成功，记录数: %d", count)
			time.Sleep(100 * time.Millisecond)
		}
		t.Log("主库读取测试完成")
	}()

	// 同时进行日志库写入操作
	wg.Add(1)
	go func() {
		defer wg.Done()
		db := global.GWAF_LOCAL_LOG_DB
		if db == nil {
			errChan <- nil
			return
		}

		// 模拟多次写入操作
		for i := 0; i < 10; i++ {
			// 插入测试数据
			err := db.Exec("INSERT INTO web_logs (REQ_UUID, tenant_id, user_code, src_ip, unix_add_time, task_flag) VALUES (?, ?, ?, ?, ?, ?)",
				"test_uuid_"+time.Now().Format("15.04.05.000"), "test_tenant", "test_user", "192.168.1.1",
				time.Now().Unix(), 0).Error
			if err != nil {
				t.Logf("日志库写入失败: %v", err)
				errChan <- err
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Log("日志库写入测试完成")
	}()

	// 同时进行日志库读取操作
	wg.Add(1)
	go func() {
		defer wg.Done()
		db := global.GWAF_LOCAL_LOG_DB
		if db == nil {
			errChan <- nil
			return
		}

		// 模拟多次读取操作
		for i := 0; i < 10; i++ {
			var count int64
			err := db.Table("web_logs").Where("user_code = ?", "test_user").Count(&count).Error
			if err != nil {
				t.Logf("日志库读取失败: %v", err)
				errChan <- err
				return
			}
			t.Logf("日志库读取成功，记录数: %d", count)
			time.Sleep(100 * time.Millisecond)
		}
		t.Log("日志库读取测试完成")
	}()

	// 同时进行统计库写入操作
	wg.Add(1)
	go func() {
		defer wg.Done()
		db := global.GWAF_LOCAL_STATS_DB
		if db == nil {
			errChan <- nil
			return
		}

		// 模拟多次写入操作
		for i := 0; i < 10; i++ {
			// 插入测试数据
			err := db.Exec("INSERT INTO stats_days (tenant_id, user_code, host_code, type, day, count) VALUES (?, ?, ?, ?, ?, ?)",
				"test_tenant", "test_user", "test_host", 1, time.Now().Format("20060102"), i).Error
			if err != nil {
				t.Logf("统计库写入失败: %v", err)
				errChan <- err
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Log("统计库写入测试完成")
	}()

	// 同时进行统计库读取操作
	wg.Add(1)
	go func() {
		defer wg.Done()
		db := global.GWAF_LOCAL_STATS_DB
		if db == nil {
			errChan <- nil
			return
		}

		// 模拟多次读取操作
		for i := 0; i < 10; i++ {
			var count int64
			err := db.Table("stats_days").Where("user_code = ?", "test_user").Count(&count).Error
			if err != nil {
				t.Logf("统计库读取失败: %v", err)
				errChan <- err
				return
			}
			t.Logf("统计库读取成功，记录数: %d", count)
			time.Sleep(100 * time.Millisecond)
		}
		t.Log("统计库读取测试完成")
	}()

	// 等待所有操作完成
	wg.Wait()
	close(errChan)

	// 检查是否有错误发生
	for err := range errChan {
		if err != nil {
			success = false
			t.Errorf("测试过程中发生错误: %v", err)
		}
	}

	if success {
		t.Log("测试通过：创建索引过程不影响数据库的读写操作")
	} else {
		t.Error("测试失败：创建索引过程影响了数据库的读写操作")
	}

	// 清理测试数据
	cleanupTestData(t)
}

// cleanupTestData 清理测试数据
func cleanupTestData(t *testing.T) {
	t.Log("开始清理测试数据...")

	// 清理主库测试数据
	if global.GWAF_LOCAL_DB != nil {
		err := global.GWAF_LOCAL_DB.Exec("DELETE FROM ip_tags WHERE user_code = ?", "test_user").Error
		if err != nil {
			t.Logf("清理主库测试数据失败: %v", err)
		}
	}

	// 清理日志库测试数据
	if global.GWAF_LOCAL_LOG_DB != nil {
		err := global.GWAF_LOCAL_LOG_DB.Exec("DELETE FROM web_logs WHERE user_code = ?", "test_user").Error
		if err != nil {
			t.Logf("清理日志库测试数据失败: %v", err)
		}
	}

	// 清理统计库测试数据
	if global.GWAF_LOCAL_STATS_DB != nil {
		err := global.GWAF_LOCAL_STATS_DB.Exec("DELETE FROM stats_days WHERE user_code = ?", "test_user").Error
		if err != nil {
			t.Logf("清理统计库测试数据失败: %v", err)
		}
	}

	t.Log("测试数据清理完成")
}
