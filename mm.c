#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))


// 매크로, 상수 선언
#define WSIZE 4             // 워드 사이즈
#define DSIZE 8             // 더블 워드 사이즈
#define CHUNKSIZE (1 << 12) // 초기 가용 블록과 힙 확장을 위한 기본 크기 선언

#define MAX(x, y) ((x) > (y) ? (x) : (y))

// 사이즈와 할당 비트를 합쳐서 헤더와 풋터에 저장할 수 있는 값을 반환
#define PACK(size, alloc) ((size) | (alloc))

// 특정 주소 p에 워드 읽기/쓰기 함수
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

// 특정 주소 p에 해당하는 블록의 사이즈와 가용 여부를 확인함
#define GET_SIZE(p) ((GET(p) >> 3) << 3)

#define GET_ALLOC(p) (GET(p) & 0x1)

#define GET_PREV_ALLOC(p) (GET(HDRP(p)) & 0x2)
#define ALLOC_PREV_HDRP(p) (GET(HDRP(p)) |= 0x2)
#define FREE_PREV_HDRP(p) (GET(HDRP(p)) &= ~0x2)

// 특정 주소 p에 해당하는 블록의 헤더와 풋터의 포인터 주소를 읽어온다
#define HDRP(ptr) ((char *)(ptr)-WSIZE)
#define FTRP(ptr) ((char *)(ptr) + GET_SIZE(HDRP(ptr)) - DSIZE)

// 다음, 이전 블록의 헤더 이후의 시작 위치의 포인터 주소를 반환
#define NEXT_BLKP(ptr) (((char *)(ptr) + GET_SIZE((char *)(ptr)-WSIZE)))
#define PREV_BLKP(ptr) (((char *)(ptr)-GET_SIZE((char *)(ptr)-DSIZE)))

// 전역 변수 및 함수 선언
static void *heap_listp;
static void *lastPoint;
static void *extend_heap(size_t words);
static void *coalesce(void *ptr);
static void *find_fit(size_t asize);
static void place(void *ptr, size_t asize);
void mm_free(void *ptr);
void *mm_realloc(void *ptr, size_t size);
void *mm_malloc(size_t size);
// 여기까지



/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    // mem_sbrk: 힙 영역을 incr(0이 아닌 양수) bytes 만큼 확장하고, 새로 할당된 힙 영역의 첫번째 byte를 가리키는 제네릭 포인터를 리턴함
    /* 비어있는 heap을 만든다.*/
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
    {
        return -1;
    };

    PUT(heap_listp, 0);                            // Alignment padding
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1)); // Prologue header
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1)); // Prologue footer
    PUT(heap_listp + (3 * WSIZE), PACK(0, 3));     // Epilogue header
    heap_listp += (2 * WSIZE);
    lastPoint = heap_listp;

    extend_heap(4);
    // 힙 영역을 확장하는 함수. 
    // 두 가지 경우에 호출된다.
    // (1) 힙이 초기화 될때 (2) mm_malloc이 적당한 맞춤fit을 찾지 못했을 때
    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
    {
        return -1;
    }

    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */

void *mm_malloc(size_t size)
{
    size_t asize;
    size_t extendsize;
    char *ptr;

    /* 의미 없는 요청 처리 안함 */
    if (size == 0)
    {
        return NULL;
    }
    // 12 - 4 + 8 + 7 = 23 2
    asize = DSIZE * ((size + (WSIZE) + (DSIZE - 1)) / DSIZE);










    // 가용 블록을 가용리스트에서 검색하고 할당기는 요청한 블록을 배치한다.
    if ((ptr = find_fit(asize)) != NULL)
    {
        place(ptr, asize);
        lastPoint = ptr;
        return ptr;
    }

    /* 리스트에 들어갈 수 있는 free 리스트가 없을 경우, 메모리를 확장하고 블록을 배치한다 */
    extendsize = MAX(asize, CHUNKSIZE);
    if ((ptr = extend_heap(extendsize / WSIZE)) == NULL)
        return NULL;
    place(ptr, asize);

    return ptr;
}
// 메모리 영역에 메모리 블록을 위치시키는 함수
static void place(void *ptr, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(ptr));

    // 블록 내의 할당 부분를 제외한 나머지 공간의 크기가 더블 워드 이상이라면, 해당 블록의 공간을 분할한다.
    if ((csize - asize) >= (DSIZE))
    {
        size_t prevAlloc = GET_PREV_ALLOC(ptr);
        PUT(HDRP(ptr), PACK(asize, 1));
        if(prevAlloc) ALLOC_PREV_HDRP(ptr);


        ptr = NEXT_BLKP(ptr);
        PUT(HDRP(ptr), PACK(csize - asize, 2));
        PUT(FTRP(ptr), PACK(csize - asize, 0));
    }
    // 블록 내의 할당 부분을 제외한 나머지 공간의 크기가 2 * 더블 워드(8byte)보다 작을 경우에는, 그냥 해당 블록의 크기를 그대로 사용한다
    else 
    {
        size_t prevAlloc = GET_PREV_ALLOC(ptr);
        PUT(HDRP(ptr), PACK(csize, 1));
        if(prevAlloc) ALLOC_PREV_HDRP(ptr);

        // PUT(FTRP(ptr), PACK(csize, 1));
        ALLOC_PREV_HDRP(NEXT_BLKP(ptr));
    }
}
//first fit
static void *find_fit(size_t asize)
{
    void *ptr;

    // 에필로그 헤더(힙의 끝) 까지 탐색한다
    for (ptr = lastPoint; GET_SIZE(HDRP(ptr)) > 0; ptr = NEXT_BLKP(ptr))
    {
        // 할당 X and 여유 공간의 크기가 할당 할 크기보다 넉넉할 경우에만
        if (!GET_ALLOC(HDRP(ptr)) && (asize <= GET_SIZE(HDRP(ptr))))
        {
            return ptr;
        }
    }
    return NULL;
}
static void *extend_heap(size_t words)
{
    char *ptr;
    size_t size;
    /* 정렬을 유지하기 위해 짝수 개수의 워드를 할당한다 */
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
    if ((long)(ptr = mem_sbrk(size)) == -1)
        return NULL;

    /* 할당되지 않은 free 상태인 블록의 헤더/풋터와 에필로그 헤더를 초기화한다 */
    
    size_t prevAlloc = GET_PREV_ALLOC(ptr);
    PUT(HDRP(ptr), PACK(size, 0));
    if(prevAlloc) ALLOC_PREV_HDRP(ptr);

    PUT(FTRP(ptr), PACK(size, 0));         // free 블록의 footer
    PUT(HDRP(NEXT_BLKP(ptr)), PACK(0, 1)); // new epilogue header

    /* 만약 이전 블록이 free 였다면, coalesce(통합) 한다*/
    return coalesce(ptr);
}
/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));

    //내 다음 블록에 가용여부 갱신
    FREE_PREV_HDRP(NEXT_BLKP(ptr));

    //기존의 가용여부 체크해서 갱신
    size_t prevAlloc = GET_PREV_ALLOC(ptr);
    PUT(HDRP(ptr), PACK(size, 0));
    if(prevAlloc) ALLOC_PREV_HDRP(ptr);

    PUT(FTRP(ptr), PACK(size, 0));

    coalesce(ptr);
}

// 할당된 블록을 합칠 수 있는 경우 4가지에 따라 메모리 연결
static void *coalesce(void *ptr)
{
    //size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(ptr))); // 이전 블록의 할당 여부
    size_t prev_alloc = GET_PREV_ALLOC(ptr); // 이전 블록의 할당 여부
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr))); // 다음 블록의 할당 여부
    size_t size = GET_SIZE(HDRP(ptr));                   // 현재 블록의 사이즈

    // 이전 블록이랑 다음 블록이 모두 할당되어 있다면, 그대로 반환
    if (prev_alloc && next_alloc) 
    {
        return ptr;
    }
    // 다음 블록이 이미 할당 되어 있고, 이전 블록이 free 라면
    else if (prev_alloc && !next_alloc)
    {
        size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
        PUT(HDRP(ptr), PACK(size, 2));
        PUT(FTRP(ptr), PACK(size, 0));
    }
    // 다음 블록이 이미 할당 되어 있고, 이전 블록이 free 라면
    else if (!prev_alloc && next_alloc) 
    {
        size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
        PUT(FTRP(ptr), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 2));
        ptr = PREV_BLKP(ptr);
    }
    // 이전과 다음 블록이 모두 free일 경우
    else 
    {
        size += GET_SIZE(HDRP(PREV_BLKP(ptr))) + GET_SIZE(FTRP(NEXT_BLKP(ptr)));
        PUT(HDRP(PREV_BLKP(ptr)), PACK(size, 2));
        PUT(FTRP(NEXT_BLKP(ptr)), PACK(size, 0));
        ptr = PREV_BLKP(ptr);
    }
    lastPoint = ptr;
    return ptr;
}
/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return mm_malloc(size);
    }

    if (size == 0) {
        mm_free(ptr);
        return NULL;
    } 

    void *new_ptr = mm_malloc(size);
    if (new_ptr == NULL) {
        return NULL;
    }
    size_t csize = GET_SIZE(HDRP(ptr));
    if (size < csize) { // 재할당 요청에 들어온 크기보다, 기존 블록의 크기가 크다면
        csize = size; // 기존 블록의 크기를 요청에 들어온 크기 만큼으로 줄인다.
    }
    memcpy(new_ptr, ptr, csize); // ptr 위치에서 csize만큼의 크기를 new_ptr의 위치에 복사함
    mm_free(ptr); // 기존 ptr의 메모리는 할당 해제해줌
    return new_ptr;
}