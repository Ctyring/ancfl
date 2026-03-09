/**
 * @file stream.h
 * @brief 流接�? */
#ifndef __ANCFL_STREAM_H__
#define __ANCFL_STREAM_H__

#include <memory>
#include "bytearray.h"

namespace ancfl {

/**
 * @brief 流结�? */
class Stream {
   public:
    typedef std::shared_ptr<Stream> ptr;
    /**
     * @brief 析构函数
     */
    virtual ~Stream() {}

    /**
     * @brief 读数�?     * @param[out] buffer 接收数据的内�?     * @param[in] length 接收数据的内存大�?     * @return
     *      @retval >0 返回接收到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int read(void* buffer, size_t length) = 0;

    /**
     * @brief 读数�?     * @param[out] ba 接收数据的ByteArray
     * @param[in] length 接收数据的内存大�?     * @return
     *      @retval >0 返回接收到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int read(ByteArray::ptr ba, size_t length) = 0;

    /**
     * @brief 读固定长度的数据
     * @param[out] buffer 接收数据的内�?     * @param[in] length 接收数据的内存大�?     * @return
     *      @retval >0 返回接收到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int readFixSize(void* buffer, size_t length);

    /**
     * @brief 读固定长度的数据
     * @param[out] ba 接收数据的ByteArray
     * @param[in] length 接收数据的内存大�?     * @return
     *      @retval >0 返回接收到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int readFixSize(ByteArray::ptr ba, size_t length);

    /**
     * @brief 写数�?     * @param[in] buffer 写数据的内存
     * @param[in] length 写入数据的内存大�?     * @return
     *      @retval >0 返回写入到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int write(const void* buffer, size_t length) = 0;

    /**
     * @brief 写数�?     * @param[in] ba 写数据的ByteArray
     * @param[in] length 写入数据的内存大�?     * @return
     *      @retval >0 返回写入到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int write(ByteArray::ptr ba, size_t length) = 0;

    /**
     * @brief 写固定长度的数据
     * @param[in] buffer 写数据的内存
     * @param[in] length 写入数据的内存大�?     * @return
     *      @retval >0 返回写入到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int writeFixSize(const void* buffer, size_t length);

    /**
     * @brief 写固定长度的数据
     * @param[in] ba 写数据的ByteArray
     * @param[in] length 写入数据的内存大�?     * @return
     *      @retval >0 返回写入到的数据的实际大�?     *      @retval =0 被关�?     *      @retval <0 出现流错�?     */
    virtual int writeFixSize(ByteArray::ptr ba, size_t length);

    /**
     * @brief 关闭�?     */
    virtual void close() = 0;
};

}  // namespace ancfl

#endif



